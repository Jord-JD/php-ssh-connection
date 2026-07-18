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

    public function testRecursiveDownloadRefusesSymbolicLinks()
    {
        $connection = $this->createKeyConnection();
        $remoteRootPath = '/tmp/php-ssh-connection-symlink-' . uniqid('', true);
        $localRootPath = $this->newTemporaryLocalPath('php-ssh-connection-symlink-');

        $connection->runCommands([
            'mkdir -p ' . escapeshellarg($remoteRootPath),
            'ln -s . ' . escapeshellarg($remoteRootPath . '/loop'),
        ]);

        try {
            $connection->download($remoteRootPath, $localRootPath);
            $this->fail('Recursive download should reject symbolic links.');
        } catch (RuntimeException $exception) {
            $this->assertNotFalse(strpos($exception->getMessage(), 'symbolic link'));
        } finally {
            $this->removeLocalPath($localRootPath);
            $connection->run('rm -rf ' . escapeshellarg($remoteRootPath));
        }
    }

    public function testSSHConnectionWithKeyPair()
    {
        $connection = $this->createKeyConnection();

        $command = $connection->run('echo "Hello world!"');

        $this->assertSame('Hello world!', $command->getOutput());
        $this->assertSame("Hello world!\n", $command->getRawOutput());

        $this->assertSame('', $command->getError());
        $this->assertSame('', $command->getRawError());
        $this->assertSame(0, $command->getExitStatus());
        $this->assertTrue($command->isSuccessful());
        $this->assertFalse($command->hasTimedOut());
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

    public function testSSHConnectionWithEncryptedPrivateKey()
    {
        $privateKeyPath = getenv('SSH_TEST_ENCRYPTED_PRIVATE_KEY_PATH');
        $passphrase = getenv('SSH_TEST_ENCRYPTED_PRIVATE_KEY_PASSPHRASE');

        if (!$privateKeyPath || !$passphrase) {
            $this->markTestSkipped('Set encrypted private key path and passphrase variables to run this test.');
        }

        $connection = $this->createBaseConnection()
            ->withPrivateKey($privateKeyPath, $passphrase)
            ->connect();

        $this->assertSame('encrypted-key-ok', $connection->run('printf encrypted-key-ok')->getOutput());
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

    public function testCommandExitStatusAndStandardError()
    {
        $command = $this->createKeyConnection()->run('printf problem >&2; exit 7');

        $this->assertSame('', $command->getOutput());
        $this->assertSame('problem', $command->getError());
        $this->assertSame(7, $command->getExitStatus());
        $this->assertFalse($command->isSuccessful());
        $this->assertFalse($command->hasTimedOut());
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
        $this->assertSame(1, preg_match('/^(?:[0-9a-f]{2}:){15}[0-9a-f]{2}$/', $connection1->fingerprint()));
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
        $this->assertSame(1, preg_match('/^[A-Za-z0-9+\/]{43}$/', $connection1->fingerprint(SSHConnection::FINGERPRINT_SHA256)));
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

    public function testExpectedFingerprintAllowsMatchingHostBeforeAuthentication()
    {
        $fingerprint = $this->createKeyConnection()->fingerprint(SSHConnection::FINGERPRINT_SHA256);
        $connection = $this->createKeyConfiguredConnection()
            ->withExpectedFingerprint('SHA256:'.$fingerprint)
            ->connect();

        $this->assertTrue($connection->isConnected());
        $this->assertNotFalse(strpos($connection->hostPublicKey(), ' '));
    }

    public function testExpectedFingerprintRejectsDifferentHostKey()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Host key fingerprint does not match');

        $this->createKeyConfiguredConnection()
            ->withExpectedFingerprint('SHA256:'.str_repeat('A', 43))
            ->connect();
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
        return $this->createKeyConfiguredConnection()->connect();
    }

    private function createKeyConfiguredConnection(): SSHConnection
    {
        $privateKeyPath = getenv('SSH_TEST_PRIVATE_KEY_PATH') ?: null;
        $privateKeyContents = getenv('SSH_TEST_PRIVATE_KEY_CONTENTS');

        if (!$privateKeyPath && ($privateKeyContents === false || $privateKeyContents === '')) {
            $this->markTestSkipped('Set SSH_TEST_PRIVATE_KEY_PATH or SSH_TEST_PRIVATE_KEY_CONTENTS to run this test.');
        }

        $connection = $this->createBaseConnection();

        if ($privateKeyContents !== false && $privateKeyContents !== '') {
            $connection->withPrivateKeyString($privateKeyContents);
        } else {
            $connection->withPrivateKey($privateKeyPath);
        }

        return $connection;
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
