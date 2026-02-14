# PHP SSH Connection

[![Build Status](https://travis-ci.com/Jord-JD/php-ssh-connection.svg?branch=master)](https://travis-ci.com/Jord-JD/php-ssh-connection)
[![Coverage Status](https://coveralls.io/repos/github/Jord-JD/php-ssh-connection/badge.svg?branch=master)](https://coveralls.io/github/Jord-JD/php-ssh-connection?branch=master)

The PHP SSH Connection package provides an elegant syntax to connect to SSH servers and execute commands. It supports both password and public-private keypair authentication, and can easily capture command output and errors.

## Installation

You can install the PHP SSH Connection package by running the following Composer command.

```bash
composer require jord-jd/php-ssh-connection
```

## Usage

See the following basic usage instructions.

```php
$connection = (new SSHConnection())
            ->to('test.rebex.net')
            ->onPort(22)
            ->as('demo')
            ->withPassword('password')
         // ->withPrivateKey($privateKeyPath)
         // ->timeout(0)
            ->connect();

$command = $connection->run('echo "Hello world!"');

$command->getOutput();  // 'Hello World'
$command->getError();   // ''

$connection->upload($localPath, $remotePath);
$connection->download($remotePath, $localPath);
```

For security, you can fingerprint the remote server and verify the fingerprint remains the same 
upon each subsequent connection.

```php
$fingerprint = $connection->fingerprint();

if ($newConnection->fingerprint() != $fingerprint) {
    throw new Exception('Fingerprint does not match!');
}
```

If you wish, you can specify the type of fingerprint you wish to retrieve.

```php
$md5Fingerprint  = $connection->fingerprint(SSHConnection::FINGERPRINT_MD5); // default
$sha1Fingerprint = $connection->fingerprint(SSHConnection::FINGERPRINT_SHA1);
```
