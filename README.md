# PHP SSH Connection

[![Tests](https://github.com/Jord-JD/php-ssh-connection/actions/workflows/tests.yml/badge.svg)](https://github.com/Jord-JD/php-ssh-connection/actions/workflows/tests.yml)

The PHP SSH Connection package provides an elegant syntax to connect to SSH servers and execute commands. It supports password and public-private key authentication, and can capture command output and errors.

## Installation

Install with Composer:

```bash
composer require jord-jd/php-ssh-connection
```

## Usage

```php
$connection = (new SSHConnection())
            ->to('test.rebex.net')
            ->onPort(22)
            ->as('demo')
            ->withPassword('password')
         // ->withPrivateKey($privateKeyPath)
         // ->withPrivateKeyString($privateKeyContents)
         // ->timeout(30)
            ->connect();

$command = $connection->run('echo "Hello world!"');

$command->getOutput();  // 'Hello world!'
$command->getError();   // ''

$connection->upload($localPath, $remotePath);
$connection->download($remotePath, $localPath); // supports recursive directory downloads
```

### Running multiple commands

Each `run()` call executes in a fresh shell context. If you need stateful command execution (for example `cd` then `touch`), use `runCommands()`:

```php
$connection->runCommands([
    'cd /var/www/html',
    'mkdir -p app',
    'cd app',
    'touch index.php',
]);
```

### Fingerprint verification

For security, you can fingerprint the remote server and verify it remains the same across connections.

```php
$fingerprint = $connection->fingerprint(); // defaults to MD5 for backward compatibility

if ($newConnection->fingerprint() !== $fingerprint) {
    throw new Exception('Fingerprint does not match!');
}
```

Available fingerprint types:

```php
$md5Fingerprint    = $connection->fingerprint(SSHConnection::FINGERPRINT_MD5);
$sha1Fingerprint   = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA1);
$sha256Fingerprint = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA256);
$sha512Fingerprint = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA512);
```

## Testing

The package test suite includes SSH integration tests. Set these variables before running tests:

- `RUN_SSH_INTEGRATION_TESTS=1`
- `SSH_TEST_HOST`
- `SSH_TEST_PORT`
- `SSH_TEST_USER`
- `SSH_TEST_PRIVATE_KEY_PATH` or `SSH_TEST_PRIVATE_KEY_CONTENTS`
- `SSH_TEST_PASSWORD` (only required for password-auth test)

Then run:

```bash
vendor/bin/phpunit
```
