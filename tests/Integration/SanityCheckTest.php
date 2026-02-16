<?php

use JordJD\SSHConnection\SSHConnection;
use PHPUnit\Framework\TestCase;

final class SanityCheckTest extends TestCase
{
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
