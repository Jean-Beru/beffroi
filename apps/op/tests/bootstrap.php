<?php

declare(strict_types=1);

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__) . '/vendor/autoload.php';

// The environment of the application itself, read from the same files the console and the kernel read:
// ".env", then ".env.test", and never ".env.local", which Dotenv leaves out of the test environment.
new Dotenv()->bootEnv(dirname(__DIR__) . '/.env');
