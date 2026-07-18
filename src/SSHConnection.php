<?php

namespace JordJD\SSHConnection;

use InvalidArgumentException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Net\SFTP;
use phpseclib3\Net\SSH2;
use RuntimeException;
use Throwable;

class SSHConnection
{
    const FINGERPRINT_MD5 = 'md5';
    const FINGERPRINT_SHA1 = 'sha1';
    const FINGERPRINT_SHA256 = 'sha256';
    const FINGERPRINT_SHA512 = 'sha512';

    private $hostname;
    private $port = 22;
    private $username;
    private $password;
    private $privateKeyPath;
    private $privateKeyContents;
    private $privateKeyPassphrase;
    private $timeout;
    private $expectedFingerprint;
    private $expectedFingerprintType;
    private $connected = false;
    private $ssh;

    public function to(string $hostname): self
    {
        if (trim($hostname) === '') {
            throw new InvalidArgumentException('Hostname must not be empty.');
        }

        $this->hostname = $hostname;
        return $this;
    }

    public function onPort(int $port): self
    {
        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException('Port must be between 1 and 65535.');
        }

        $this->port = $port;
        return $this;
    }

    public function as(string $username): self
    {
        if (trim($username) === '') {
            throw new InvalidArgumentException('Username must not be empty.');
        }

        $this->username = $username;
        return $this;
    }

    public function withPassword(string $password): self
    {
        $this->password = $password;
        return $this;
    }

    public function withPrivateKey(string $privateKeyPath, string $passphrase = null): self
    {
        if (trim($privateKeyPath) === '') {
            throw new InvalidArgumentException('Private key path must not be empty.');
        }

        $this->privateKeyPath = $privateKeyPath;
        $this->privateKeyContents = null;
        $this->privateKeyPassphrase = $passphrase;
        return $this;
    }

    public function withPrivateKeyString(string $privateKeyContents, string $passphrase = null): self
    {
        if ($privateKeyContents === '') {
            throw new InvalidArgumentException('Private key contents must not be empty.');
        }

        $this->privateKeyContents = $privateKeyContents;
        $this->privateKeyPath = null;
        $this->privateKeyPassphrase = $passphrase;
        return $this;
    }

    public function timeout(int $timeout): self
    {
        if ($timeout < 0) {
            throw new InvalidArgumentException('Timeout must be zero or a positive number of seconds.');
        }

        $this->timeout = $timeout;
        return $this;
    }

    /**
     * Require a host-key fingerprint before any authentication is attempted.
     */
    public function withExpectedFingerprint(string $fingerprint, string $type = self::FINGERPRINT_SHA256): self
    {
        if (trim($fingerprint) === '') {
            throw new InvalidArgumentException('Expected fingerprint must not be empty.');
        }

        $this->assertFingerprintType($type);
        $this->expectedFingerprint = $fingerprint;
        $this->expectedFingerprintType = $type;

        return $this;
    }

    private function sanityCheck()
    {
        if (!$this->hostname) {
            throw new InvalidArgumentException('Hostname not specified.');
        }

        if (!$this->username) {
            throw new InvalidArgumentException('Username not specified.');
        }

        if ($this->password === null && !$this->privateKeyPath && !$this->privateKeyContents) {
            throw new InvalidArgumentException('No password or private key specified.');
        }
    }

    public function connect(): self
    {
        $this->sanityCheck();

        $this->ssh = $this->createAuthenticatedClient(SSH2::class);

        $this->connected = true;

        return $this;
    }

    public function disconnect()
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to disconnect. Not yet connected.');
        }

        $this->ssh->disconnect();
        $this->connected = false;
    }

    public function run(string $command): SSHCommand
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to run commands when not connected.');
        }

        if (trim($command) === '') {
            throw new InvalidArgumentException('Command must not be empty.');
        }

        return new SSHCommand($this->ssh, $command);
    }

    public function runCommands(array $commands, string $separator = '&&'): SSHCommand
    {
        if (!$commands) {
            throw new InvalidArgumentException('No commands specified.');
        }

        $separator = trim($separator);
        if (!$separator) {
            throw new InvalidArgumentException('Invalid command separator specified.');
        }

        $filteredCommands = [];

        foreach ($commands as $command) {
            if (!is_string($command) || !trim($command)) {
                throw new InvalidArgumentException('All commands must be non-empty strings.');
            }

            $filteredCommands[] = trim($command);
        }

        return $this->run(implode(' ' . $separator . ' ', $filteredCommands));
    }

    public function fingerprint(string $type = self::FINGERPRINT_MD5)
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to get fingerprint when not connected.');
        }

        return $this->fingerprintClient($this->ssh, $type);
    }

    public function hostPublicKey(): string
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to get host public key when not connected.');
        }

        return $this->getHostPublicKey($this->ssh);
    }

    public function upload(string $localPath, string $remotePath): bool
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to upload file when not connected.');
        }

        if (!is_file($localPath) || !is_readable($localPath)) {
            throw new InvalidArgumentException('The local file does not exist or is not readable.');
        }

        if (trim($remotePath) === '') {
            throw new InvalidArgumentException('Remote upload path must not be empty.');
        }

        $sftp = $this->createSftpClient();

        return $sftp->put($remotePath, $localPath, SFTP::SOURCE_LOCAL_FILE);
    }

    public function download(string $remotePath, string $localPath): bool
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to download file when not connected.');
        }

        if (trim($remotePath) === '' || trim($localPath) === '') {
            throw new InvalidArgumentException('Remote and local download paths must not be empty.');
        }

        $sftp = $this->createSftpClient();

        if ($sftp->is_dir($remotePath)) {
            return $this->downloadDirectory($sftp, $remotePath, $localPath);
        }

        return $sftp->get($remotePath, $localPath);
    }

    public function isConnected(): bool
    {
        return $this->connected;
    }

    private function authenticateClient(SSH2 $client)
    {
        $privateKey = $this->getPrivateKey();

        if ($privateKey) {
            $authenticated = $client->login($this->username, $privateKey);
            if ($authenticated) {
                return;
            }

            if ($this->password === null) {
                throw new RuntimeException('Error authenticating with public-private key pair.');
            }
        }

        if ($this->password !== null) {
            $authenticated = $client->login($this->username, $this->password);
            if ($authenticated) {
                return;
            }

            throw new RuntimeException('Error authenticating with password.');
        }
    }

    private function getPrivateKey()
    {
        $privateKeyContents = $this->privateKeyContents;

        if (!$privateKeyContents && $this->privateKeyPath) {
            if (!is_file($this->privateKeyPath) || !is_readable($this->privateKeyPath)) {
                throw new InvalidArgumentException('Unable to read private key file.');
            }

            $privateKeyContents = @file_get_contents($this->privateKeyPath);
            if ($privateKeyContents === false) {
                throw new InvalidArgumentException('Unable to read private key file.');
            }
        }

        if (!$privateKeyContents) {
            return null;
        }

        try {
            return PublicKeyLoader::loadPrivateKey(
                $privateKeyContents,
                $this->privateKeyPassphrase === null ? false : $this->privateKeyPassphrase
            );
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('Invalid private key or passphrase provided.', 0, $exception);
        }
    }

    private function createSftpClient()
    {
        return $this->createAuthenticatedClient(SFTP::class);
    }

    private function downloadDirectory(SFTP $sftp, string $remotePath, string $localPath): bool
    {
        if (!is_dir($localPath) && !mkdir($localPath, 0755, true) && !is_dir($localPath)) {
            throw new RuntimeException('Unable to create local directory.');
        }

        $entries = $sftp->nlist($remotePath);
        if ($entries === false) {
            return false;
        }

        foreach ($entries as $entry) {
            $entryName = basename($entry);
            if ($entryName === '.' || $entryName === '..') {
                continue;
            }

            $remoteEntryPath = $this->joinRemotePath($remotePath, $entryName);
            $localEntryPath = rtrim($localPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entryName;

            if ($sftp->is_link($remoteEntryPath)) {
                throw new RuntimeException('Refusing to follow a symbolic link during recursive download: '.$remoteEntryPath);
            }

            if ($sftp->is_dir($remoteEntryPath)) {
                if (!$this->downloadDirectory($sftp, $remoteEntryPath, $localEntryPath)) {
                    return false;
                }
                continue;
            }

            if (!$sftp->get($remoteEntryPath, $localEntryPath)) {
                return false;
            }
        }

        return true;
    }

    private function joinRemotePath(string $basePath, string $path): string
    {
        return rtrim($basePath, '/') . '/' . ltrim($path, '/');
    }

    private function createAuthenticatedClient($clientClass)
    {
        $timeout = $this->timeout === null ? 10 : $this->timeout;
        $client = new $clientClass($this->hostname, $this->port, $timeout);

        if ($this->expectedFingerprint !== null) {
            $actualFingerprint = $this->fingerprintClient($client, $this->expectedFingerprintType);
            $expectedFingerprint = $this->normalizeFingerprint($this->expectedFingerprint, $this->expectedFingerprintType);
            $normalizedActual = $this->normalizeFingerprint($actualFingerprint, $this->expectedFingerprintType);

            if (!hash_equals($expectedFingerprint, $normalizedActual)) {
                throw new RuntimeException('Host key fingerprint does not match the expected fingerprint.');
            }
        }

        $this->authenticateClient($client);

        if ($this->timeout !== null) {
            $client->setTimeout($this->timeout);
        }

        return $client;
    }

    private function fingerprintClient(SSH2 $client, string $type): string
    {
        $this->assertFingerprintType($type);
        $hostKeyBlob = $this->decodeHostPublicKey($this->getHostPublicKey($client));

        if ($type === self::FINGERPRINT_MD5) {
            return implode(':', str_split(md5($hostKeyBlob), 2));
        }

        if ($type === self::FINGERPRINT_SHA256) {
            return rtrim(base64_encode(hash('sha256', $hostKeyBlob, true)), '=');
        }

        return hash($type, $hostKeyBlob);
    }

    private function getHostPublicKey(SSH2 $client): string
    {
        $hostKey = $client->getServerPublicHostKey();

        if (!is_string($hostKey) || trim($hostKey) === '') {
            throw new RuntimeException('Unable to retrieve or verify the server host key.');
        }

        return $hostKey;
    }

    private function decodeHostPublicKey($hostKey)
    {
        $parts = preg_split('/\s+/', trim($hostKey), 3);

        if (count($parts) < 2) {
            throw new RuntimeException('Server host key is not in OpenSSH format.');
        }

        $blob = base64_decode($parts[1], true);

        if ($blob === false) {
            throw new RuntimeException('Server host key payload is not valid base64.');
        }

        return $blob;
    }

    private function assertFingerprintType($type)
    {
        if (!in_array($type, [self::FINGERPRINT_MD5, self::FINGERPRINT_SHA1, self::FINGERPRINT_SHA256, self::FINGERPRINT_SHA512], true)) {
            throw new InvalidArgumentException('Invalid fingerprint type specified.');
        }
    }

    private function normalizeFingerprint($fingerprint, $type)
    {
        $fingerprint = trim($fingerprint);
        $prefix = strtoupper($type).':';

        if (stripos($fingerprint, $prefix) === 0) {
            $fingerprint = substr($fingerprint, strlen($prefix));
        }

        if ($type === self::FINGERPRINT_SHA256) {
            return rtrim($fingerprint, '=');
        }

        return strtolower(str_replace(':', '', $fingerprint));
    }
}
