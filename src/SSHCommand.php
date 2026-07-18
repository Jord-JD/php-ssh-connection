<?php

namespace JordJD\SSHConnection;

use phpseclib3\Net\SSH2;
use RuntimeException;

class SSHCommand
{
    const EXECUTION_TIMEOUT_SECONDS = 30;
    const STREAM_BYTES_PER_READ = 4096;

    private $ssh;
    private $command;
    private $output;
    private $error;
    private $exitStatus;
    private $timedOut;

    public function __construct(SSH2 $ssh, string $command)
    {
        $this->ssh = $ssh;
        $this->command = $command;

        $this->execute();
    }

    private function execute()
    {
        $this->ssh->enableQuietMode();
        $output = $this->ssh->exec($this->command);

        if ($output === false) {
            throw new RuntimeException('SSH command could not be executed.');
        }

        $this->output = (string) $output;
        $this->error = (string) $this->ssh->getStdError();
        $exitStatus = $this->ssh->getExitStatus();
        $this->exitStatus = is_int($exitStatus) ? $exitStatus : null;
        $this->timedOut = $this->ssh->isTimeout();
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

    public function getExitStatus(): ?int
    {
        return $this->exitStatus;
    }

    public function isSuccessful(): bool
    {
        return $this->exitStatus === 0 && !$this->timedOut;
    }

    public function hasTimedOut(): bool
    {
        return $this->timedOut;
    }
}
