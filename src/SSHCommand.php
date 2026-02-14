<?php

namespace JordJD\SSHConnection;

use phpseclib\Net\SSH2;
use RuntimeException;

class SSHCommand
{
    const EXECUTION_TIMEOUT_SECONDS = 30;
    const STREAM_BYTES_PER_READ = 4096;

    private $ssh;
    private $command;
    private $output;
    private $error;

    public function __construct(SSH2 $ssh, string $command)
    {
        $this->ssh = $ssh;
        $this->command = $command;

        $this->execute();
    }

    private function execute()
    {
        $this->ssh->enableQuietMode();
        $this->output = $this->ssh->exec($this->command);
        $this->error = $this->ssh->getStdError();
    }

    public function getRawOutput(): string
    {
        return $this->output;
    }

    public function getRawError(): string
    {
        return $this->error;
    }

    public function getOutput(): string
    {
        return trim($this->getRawOutput());
    }

    public function getError(): string
    {
        return trim($this->getRawError());
    }
}