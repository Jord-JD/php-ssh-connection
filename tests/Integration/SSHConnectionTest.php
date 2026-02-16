<?php

use JordJD\SSHConnection\SSHConnection;
use PHPUnit\Framework\TestCase;

final class SSHConnectionTest extends TestCase
{
    public function testUpload()
    {
        $connection = $this->createKeyConnection();
        $remotePath = '/tmp/php-ssh-connection-upload-' . uniqid('', true) . '.txt';
        $localPath = __DIR__ . '/../fixtures/file.txt';

        $this->assertTrue($connection->upload($localPath, $remotePath));

        $existsCommand = $connection->run('test -f ' . escapeshellarg($remotePath) . ' && echo yes || echo no');
        $this->assertSame('yes', $existsCommand->getOutput());

        $connection->run('rm -f ' . escapeshellarg($remotePath));
    }

    public function testDownloadFile()
    {
        $connection = $this->createKeyConnection();
        $remotePath = '/tmp/php-ssh-connection-download-' . uniqid('', true) . '.txt';
        $localPath = $this->newTemporaryLocalPath('php-ssh-connection-download-');

        $connection->run('printf "download-content" > ' . escapeshellarg($remotePath));

        $this->assertTrue($connection->download($remotePath, $localPath));
        $this->assertFileExists($localPath);
        $this->assertSame('download-content', file_get_contents($localPath));

        @unlink($localPath);
        $connection->run('rm -f ' . escapeshellarg($remotePath));
    }

    public function testDownloadDirectoryRecursively()
    {
        $connection = $this->createKeyConnection();
        $remoteRootPath = '/tmp/php-ssh-connection-dir-' . uniqid('', true);
        $localRootPath = $this->newTemporaryLocalPath('php-ssh-connection-dir-');

        $connection->runCommands([
            'mkdir -p ' . escapeshellarg($remoteRootPath . '/nested'),
            'printf "root-file" > ' . escapeshellarg($remoteRootPath . '/root.txt'),
            'printf "child-file" > ' . escapeshellarg($remoteRootPath . '/nested/child.txt'),
        ]);

        $this->assertTrue($connection->download($remoteRootPath, $localRootPath));
        $this->assertFileExists($localRootPath . '/root.txt');
        $this->assertFileExists($localRootPath . '/nested/child.txt');
        $this->assertSame('root-file', file_get_contents($localRootPath . '/root.txt'));
        $this->assertSame('child-file', file_get_contents($localRootPath . '/nested/child.txt'));

        $this->removeLocalPath($localRootPath);
        $connection->run('rm -rf ' . escapeshellarg($remoteRootPath));
    }

    public function testSSHConnectionWithKeyPair()
    {
        $connection = $this->createKeyConnection();

        $command = $connection->run('echo "Hello world!"');

        $this->assertSame('Hello world!', $command->getOutput());
        $this->assertSame("Hello world!\n", $command->getRawOutput());

        $this->assertSame('', $command->getError());
        $this->assertSame('', $command->getRawError());
    }

    public function testSSHConnectionWithKeyContents()
    {
        $privateKeyContents = $this->getPrivateKeyContents();

        if (!$privateKeyContents) {
            $this->markTestSkipped('Set SSH_TEST_PRIVATE_KEY_PATH or SSH_TEST_PRIVATE_KEY_CONTENTS to run this test.');
        }

        $connection = $this->createBaseConnection()
            ->withPrivateKeyString($privateKeyContents)
            ->connect();

        $command = $connection->run('echo "Hello world!"');

        $this->assertSame('Hello world!', $command->getOutput());
        $this->assertSame("Hello world!\n", $command->getRawOutput());
        $this->assertSame('', $command->getError());
        $this->assertSame('', $command->getRawError());
    }

    public function testSSHConnectionWithKeyContents()
    {
        $privateKeyContents = file_get_contents('/home/travis/.ssh/id_rsa');

        $connection = (new SSHConnection())
            ->to('localhost')
            ->onPort(22)
            ->as('travis')
            ->withPrivateKeyString($privateKeyContents)
            ->connect();

        $command = $connection->run('echo "Hello world!"');

        $this->assertEquals('Hello world!', $command->getOutput());
        $this->assertEquals('Hello world!'."\n", $command->getRawOutput());

        $this->assertEquals('', $command->getError());
        $this->assertEquals('', $command->getRawError());
    }

    public function testSSHConnectionWithPassword()
    {
        $connection = $this->createPasswordConnection();

        $command = $connection->run('echo "Hello world!"');

        $this->assertSame('Hello world!', $command->getOutput());
        $this->assertSame("Hello world!\n", $command->getRawOutput());
        $this->assertSame('', $command->getError());
        $this->assertSame('', $command->getRawError());
    }

    public function testRunMultipleCommands()
    {
        $connection = $this->createKeyConnection();
        $remotePath = '/tmp/php-ssh-connection-commands-' . uniqid('', true);

        $command = $connection->runCommands([
            'mkdir -p ' . escapeshellarg($remotePath),
            'cd ' . escapeshellarg($remotePath),
            'pwd',
        ]);

        $this->assertSame($remotePath, $command->getOutput());

        $connection->run('rm -rf ' . escapeshellarg($remotePath));
    }

    public function testRunMultipleCommandsValidation()
    {
        $this->expectException(InvalidArgumentException::class);

        (new SSHConnection())->runCommands([]);
    }

    public function testMd5Fingerprint()
    {
        $connection1 = $this->createKeyConnection();
        $connection2 = $this->createKeyConnection();

        $this->assertSame(
            $connection1->fingerprint(SSHConnection::FINGERPRINT_MD5),
            $connection2->fingerprint(SSHConnection::FINGERPRINT_MD5)
        );
    }

    public function testSha1Fingerprint()
    {
        $connection1 = $this->createKeyConnection();
        $connection2 = $this->createKeyConnection();

        $this->assertSame(
            $connection1->fingerprint(SSHConnection::FINGERPRINT_SHA1),
            $connection2->fingerprint(SSHConnection::FINGERPRINT_SHA1)
        );
    }

    public function testSha256Fingerprint()
    {
        $connection1 = $this->createKeyConnection();
        $connection2 = $this->createKeyConnection();

        $this->assertSame(
            $connection1->fingerprint(SSHConnection::FINGERPRINT_SHA256),
            $connection2->fingerprint(SSHConnection::FINGERPRINT_SHA256)
        );
    }

    public function testSha512Fingerprint()
    {
        $connection1 = $this->createKeyConnection();
        $connection2 = $this->createKeyConnection();

        $this->assertSame(
            $connection1->fingerprint(SSHConnection::FINGERPRINT_SHA512),
            $connection2->fingerprint(SSHConnection::FINGERPRINT_SHA512)
        );
    }

    public function testInvalidFingerprintType()
    {
        $connection = $this->createKeyConnection();

        $this->expectException(InvalidArgumentException::class);

        $connection->fingerprint('unsupported');
    }

    private function createBaseConnection(): SSHConnection
    {
        $this->requireIntegrationTestsEnabled();

        $host = getenv('SSH_TEST_HOST') ?: '127.0.0.1';
        $port = (int) (getenv('SSH_TEST_PORT') ?: 22);
        $username = $this->getRequiredEnvironmentValue('SSH_TEST_USER');

        return (new SSHConnection())
            ->to($host)
            ->onPort($port)
            ->as($username);
    }

    private function createKeyConnection(): SSHConnection
    {
        $privateKeyPath = getenv('SSH_TEST_PRIVATE_KEY_PATH') ?: null;
        $privateKeyContents = $this->getPrivateKeyContents();

        if (!$privateKeyPath && !$privateKeyContents) {
            $this->markTestSkipped('Set SSH_TEST_PRIVATE_KEY_PATH or SSH_TEST_PRIVATE_KEY_CONTENTS to run this test.');
        }

        $connection = $this->createBaseConnection();

        if ($privateKeyContents) {
            $connection->withPrivateKeyString($privateKeyContents);
        } else {
            $connection->withPrivateKey($privateKeyPath);
        }

        return $connection->connect();
    }

    private function createPasswordConnection(): SSHConnection
    {
        $password = getenv('SSH_TEST_PASSWORD');

        if ($password === false || $password === '') {
            $this->markTestSkipped('Set SSH_TEST_PASSWORD to run this test.');
        }

        return $this->createBaseConnection()
            ->withPassword($password)
            ->connect();
    }

    private function requireIntegrationTestsEnabled()
    {
        if (getenv('RUN_SSH_INTEGRATION_TESTS') !== '1') {
            $this->markTestSkipped('Set RUN_SSH_INTEGRATION_TESTS=1 to run SSH integration tests.');
        }
    }

    private function getRequiredEnvironmentValue(string $name): string
    {
        $value = getenv($name);

        if ($value === false || $value === '') {
            $this->markTestSkipped('Missing required environment variable: ' . $name);
        }

        return $value;
    }

    private function getPrivateKeyContents()
    {
        $privateKeyContents = getenv('SSH_TEST_PRIVATE_KEY_CONTENTS');
        if ($privateKeyContents !== false && $privateKeyContents !== '') {
            return $privateKeyContents;
        }

        $privateKeyPath = getenv('SSH_TEST_PRIVATE_KEY_PATH');
        if ($privateKeyPath && is_file($privateKeyPath)) {
            return file_get_contents($privateKeyPath);
        }

        return null;
    }

    private function newTemporaryLocalPath(string $prefix): string
    {
        return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $prefix . uniqid('', true);
    }

    private function removeLocalPath(string $path)
    {
        if (!file_exists($path)) {
            return;
        }

        if (is_file($path)) {
            @unlink($path);
            return;
        }

        $entries = scandir($path);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $this->removeLocalPath($path . DIRECTORY_SEPARATOR . $entry);
        }

        @rmdir($path);
    }
}
