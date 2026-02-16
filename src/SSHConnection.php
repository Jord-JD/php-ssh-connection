<?php

namespace JordJD\SSHConnection;

use InvalidArgumentException;
use phpseclib\Crypt\RSA;
use phpseclib\Net\SCP;
use phpseclib\Net\SFTP;
use phpseclib\Net\SSH2;
use RuntimeException;

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
    private $timeout;
    private $connected = false;
    private $ssh;

    public function to(string $hostname): self
    {
        $this->hostname = $hostname;
        return $this;
    }

    public function onPort(int $port): self
    {
        $this->port = $port;
        return $this;
    }

    public function as(string $username): self
    {
        $this->username = $username;
        return $this;
    }

    public function withPassword(string $password): self
    {
        $this->password = $password;
        return $this;
    }

    public function withPrivateKey(string $privateKeyPath): self
    {
        $this->privateKeyPath = $privateKeyPath;
        $this->privateKeyContents = null;
        return $this;
    }

    public function withPrivateKeyString(string $privateKeyContents): self
    {
        $this->privateKeyContents = $privateKeyContents;
        $this->privateKeyPath = null;
        return $this;
    }

    public function withPrivateKeyString(string $privateKeyContents): self
    {
        $this->privateKeyContents = $privateKeyContents;
        return $this;
    }

    public function timeout(int $timeout): self
    {
        $this->timeout = $timeout;
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

        if (!$this->password && !$this->privateKeyPath && !$this->privateKeyContents) {
            throw new InvalidArgumentException('No password or private key specified.');
        }
    }

    public function connect(): self
    {
        $this->sanityCheck();

        $this->ssh = new SSH2($this->hostname, $this->port);

        if (!$this->ssh) {
            throw new RuntimeException('Error connecting to server.');
        }

        $this->authenticateClient($this->ssh);

        if ($this->timeout !== null) {
            $this->ssh->setTimeout($this->timeout);
        }

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

        $hostKey = substr($this->ssh->getServerPublicHostKey(), 8);

        switch ($type) {
            case self::FINGERPRINT_MD5:
                return strtoupper(md5($hostKey));

            case self::FINGERPRINT_SHA1:
                return strtoupper(sha1($hostKey));

            case self::FINGERPRINT_SHA256:
                return strtoupper(hash('sha256', $hostKey));

            case self::FINGERPRINT_SHA512:
                return strtoupper(hash('sha512', $hostKey));
        }

        throw new InvalidArgumentException('Invalid fingerprint type specified.');
    }

    public function upload(string $localPath, string $remotePath): bool
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to upload file when not connected.');
        }

        if (!file_exists($localPath)) {
            throw new InvalidArgumentException('The local file does not exist.');
        }

        return (new SCP($this->ssh))->put($remotePath, $localPath, SCP::SOURCE_LOCAL_FILE);
    }

    public function download(string $remotePath, string $localPath): bool
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to download file when not connected.');
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

            if (!$this->password) {
                throw new RuntimeException('Error authenticating with public-private key pair.');
            }
        }

        if ($this->password) {
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
            $privateKeyContents = @file_get_contents($this->privateKeyPath);
            if ($privateKeyContents === false) {
                throw new InvalidArgumentException('Unable to read private key file.');
            }
        }

        if (!$privateKeyContents) {
            return null;
        }

        $privateKey = new RSA();
        if (!$privateKey->loadKey($privateKeyContents)) {
            throw new InvalidArgumentException('Invalid private key provided.');
        }

        return $privateKey;
    }

    private function createSftpClient()
    {
        $sftp = new SFTP($this->hostname, $this->port);
        if (!$sftp) {
            throw new RuntimeException('Error connecting to server.');
        }

        $this->authenticateClient($sftp);

        if ($this->timeout !== null) {
            $sftp->setTimeout($this->timeout);
        }

        return $sftp;
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
}
