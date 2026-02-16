<?php

namespace JordJD\SSHConnection;

use InvalidArgumentException;
use phpseclib\Crypt\RSA;
use phpseclib\Net\SCP;
use phpseclib\Net\SSH2;
use RuntimeException;

class SSHConnection
{
    const FINGERPRINT_MD5 = 'md5';
    const FINGERPRINT_SHA1 = 'sha1';

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

        if ($this->privateKeyPath || $this->privateKeyContents) {
            $key = new RSA();

            if ($this->privateKeyPath) {
                $key->loadKey(file_get_contents($this->privateKeyPath));
            } else if ($this->privateKeyContents) {
                $key->loadKey($this->privateKeyContents);
            }

            $authenticated = $this->ssh->login($this->username, $key);
            if (!$authenticated) {
                throw new RuntimeException('Error authenticating with public-private key pair.');
            }
        }

        if ($this->password) {
            $authenticated = $this->ssh->login($this->username, $this->password);
            if (!$authenticated) {
                throw new RuntimeException('Error authenticating with password.');
            }
        }

        if ($this->timeout) {
            $this->ssh->setTimeout($this->timeout);
        }

        $this->connected = true;

        return $this;
    }

    public function disconnect(): void
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to disconnect. Not yet connected.');
        }

        $this->ssh->disconnect();
    }

    public function run(string $command): SSHCommand
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to run commands when not connected.');
        }

        return new SSHCommand($this->ssh, $command);
    }

    public function fingerprint(string $type = self::FINGERPRINT_MD5)
    {
        if (!$this->connected) {
            throw new RuntimeException('Unable to get fingerprint when not connected.');
        }

        $hostKey = substr($this->ssh->getServerPublicHostKey(), 8);

        switch ($type) {
            case 'md5':
                return strtoupper(md5($hostKey));

            case 'sha1':
                return strtoupper(sha1($hostKey));
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

        return (new SCP($this->ssh))->get($remotePath, $localPath);
    }

    public function isConnected(): bool
    {
        return $this->connected;
    }
}
