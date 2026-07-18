# PHP SSH Connection

[![Tests](https://github.com/Jord-JD/php-ssh-connection/actions/workflows/tests.yml/badge.svg)](https://github.com/Jord-JD/php-ssh-connection/actions/workflows/tests.yml)
[![Packagist](https://img.shields.io/packagist/v/jord-jd/php-ssh-connection.svg)](https://packagist.org/packages/jord-jd/php-ssh-connection)

The PHP SSH Connection package provides an elegant syntax to connect to SSH servers and execute commands. It supports password and public-private key authentication, and can capture command output and errors.

Supported runtimes: PHP 7.2+ and PHP 8.x.

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
         // ->withPrivateKey($encryptedPrivateKeyPath, $passphrase)
         // ->withExpectedFingerprint('SHA256:base64-fingerprint-from-a-trusted-source')
         // ->timeout(30)
            ->connect();

$command = $connection->run('echo "Hello world!"');

$command->getOutput();  // 'Hello world!'
$command->getError();   // ''
$command->getExitStatus(); // 0
$command->isSuccessful();  // true
$command->hasTimedOut();   // false

$connection->upload($localPath, $remotePath); // SFTP
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

For security, obtain the server's SHA-256 fingerprint through a trusted
out-of-band channel and configure it before connecting. Verification happens
before a password or private key is sent to the server.

```php
$connection = (new SSHConnection())
    ->to('example.com')
    ->as('username')
    ->withPrivateKey('/home/user/.ssh/id_rsa')
    ->withExpectedFingerprint('SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU')
    ->connect();
```

The `SHA256:` prefix and base64 padding are optional when configuring the
expected value. MD5 values may be supplied with or without colons.

Available fingerprint types:

```php
$md5Fingerprint    = $connection->fingerprint(SSHConnection::FINGERPRINT_MD5); // colon-separated hex
$sha1Fingerprint   = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA1);
$sha256Fingerprint = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA256); // OpenSSH base64
$sha512Fingerprint = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA512);
$openSshPublicKey  = $connection->hostPublicKey();
```

SHA-256 and MD5 match the standard OpenSSH fingerprint algorithms. SHA-1 and
SHA-512 remain available as hexadecimal hashes of the SSH wire key for callers
that previously selected those constants. The no-argument `fingerprint()` call
still defaults to MD5 for source compatibility; SHA-256 is recommended for new
code.

### Private key passphrases

Pass a private-key passphrase as the second argument for either file or string
keys:

```php
$connection->withPrivateKey('/secure/id_rsa', 'key passphrase');
$connection->withPrivateKeyString($privateKeyContents, 'key passphrase');
```

### Timeouts

`timeout()` now applies to the initial socket connection and authentication as
well as subsequent command and SFTP activity. A timeout of zero disables the
operation timeout; negative values are rejected.

### File transfer safety

Uploads and downloads both use SFTP. Recursive directory downloads refuse to
follow remote symbolic links, preventing cycles and unexpected traversal
outside the requested tree.

## Compatibility

PHP 7.2 through the current PHP 8.x releases are supported. Version 5 uses the
actively maintained phpseclib 3.x line.

### Upgrading to 5.0

- Composer now installs phpseclib 3.x instead of 2.x.
- MD5 and SHA-256 fingerprints now use standard OpenSSH representations rather
  than hashes of a truncated host-key string.
- Uploads use SFTP instead of the removed phpseclib 2 SCP client.
- Empty hostnames/usernames, out-of-range ports, negative timeouts, invalid key
  passphrases, and recursive remote symbolic links now fail explicitly.

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
