<?php

use JordJD\SSHConnection\SSHConnection;
use PHPUnit\Framework\TestCase;

final class SanityCheckTest extends TestCase
{
    public function testInvalidPort()
    {
        $this->expectException(InvalidArgumentException::class);
        (new SSHConnection())->onPort(70000);
    }

    public function testInvalidTimeout()
    {
        $this->expectException(InvalidArgumentException::class);
        (new SSHConnection())->timeout(-1);
    }

    public function testEmptyExpectedFingerprint()
    {
        $this->expectException(InvalidArgumentException::class);
        (new SSHConnection())->withExpectedFingerprint('');
    }

    public function testEmptyPrivateKeyPath()
    {
        $this->expectException(InvalidArgumentException::class);
        (new SSHConnection())->withPrivateKey('');
    }

    public function testEmptyPrivateKeyContents()
    {
        $this->expectException(InvalidArgumentException::class);
        (new SSHConnection())->withPrivateKeyString('');
    }

    public function testNoHostname()
    {
        $this->expectException(InvalidArgumentException::class);

        (new SSHConnection())
            ->onPort(22)
            ->as('ssh-test-user')
            ->withPrivateKey('/tmp/ssh-test-key')
            ->connect();
    }

    public function testNoUsername()
    {
        $this->expectException(InvalidArgumentException::class);

        (new SSHConnection())
            ->to('localhost')
            ->onPort(22)
            ->withPrivateKey('/tmp/ssh-test-key')
            ->connect();
    }

    public function testNoAuthentication()
    {
        $this->expectException(InvalidArgumentException::class);

        (new SSHConnection())
            ->to('localhost')
            ->onPort(22)
            ->as('ssh-test-user')
            ->connect();
    }
}
