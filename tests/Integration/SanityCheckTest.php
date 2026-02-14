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
            ->as('travis')
            ->withPrivateKey('/home/travis/.ssh/id_rsa')
            ->connect();
    }

    public function testNoUsername()
    {
        $this->expectException(InvalidArgumentException::class);

        (new SSHConnection())
            ->to('localhost')
            ->onPort(22)
            ->withPrivateKey('/home/travis/.ssh/id_rsa')
            ->connect();
    }

    public function testNoAuthentication()
    {
        $this->expectException(InvalidArgumentException::class);

        (new SSHConnection())
            ->to('localhost')
            ->onPort(22)
            ->as('travis')
            ->connect();
    }
}
