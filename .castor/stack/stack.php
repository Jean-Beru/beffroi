<?php

declare(strict_types=1);

/*
 * The development stack: the OP on FrankenPHP, its database and broker, the optional KMS backends and the
 * conformance suite, up, down, logs and console. What the CI starts before the conformance plans.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\io;
use function Castor\run;
use Symfony\Component\Process\Process;

/**
 * The KMS backends of the development stack, by the value "--kms" takes: the compose profile that runs
 * the backend, none for a local one, and the scheme of the DSN "castor provision" writes for it. The DSN
 * is the only difference between two of them (architecture §3.3): sodium and file are the same local
 * backend, the key inline in the environment or in a file of its own; vault and aws are a KMS on the
 * network, the master key never leaves it.
 */
const KMS_BACKENDS = [
    'sodium' => [
        'profile' => null,
        'scheme' => 'sodium',
    ],
    'file' => [
        'profile' => null,
        'scheme' => 'sodium+dir',
    ],
    'vault' => [
        'profile' => 'vault',
        'scheme' => 'hashicorp-vault-transit',
    ],
    'aws' => [
        'profile' => 'aws',
        'scheme' => 'aws-kms',
    ],
];

/**
 * Where the key of the file backend lives in the containers: the volume kms_data of compose.yaml, outside
 * the web root and outside the sealed keys, mounted on the process that serves and on the one that rotates.
 */
const KMS_FILE_DIRECTORY = '/app/var/kms';

/**
 * The compose profiles a task that stops or reads the whole stack must name.
 */
const COMPOSE_PROFILES = ['conformance', 'vault', 'aws'];

#[AsTask(description: 'Start the development stack: the OP on https://op.localhost and PostgreSQL. Add --conformance for the OpenID conformance suite on https://localhost:8443, without the profiler; --access-token-format opaque hands the clients of the suite opaque access tokens; --kms vault adds HashiCorp Vault, --kms aws adds Floci (AWS KMS), each sealing the signing keys once "castor provision --kms <backend>" ran')]
function start(
    bool $conformance = false,
    bool $build = false,
    #[AsOption(description: 'The access token shape of the clients of the conformance suite: jwt (default) or opaque; the plans must be green with either')]
    ?string $accessTokenFormat = null,
    #[AsOption(description: 'The KMS that seals the signing keys: sodium (default) or file (in the process, nothing to start), vault (HashiCorp Vault Transit, dev mode, initialised at every start by docker/vault/init.sh) or aws (the KMS of Floci, an AWS emulator, initialised at every start by docker/floci/init.sh)')]
    string $kms = 'sodium',
): void {
    if ($accessTokenFormat !== null && ! in_array($accessTokenFormat, ['jwt', 'opaque'], true)) {
        io()->error(sprintf('Unknown access token format "%s"; the formats are jwt and opaque.', $accessTokenFormat));
        exit(1);
    }
    $backend = kms_backend($kms);
    $command = ['docker', 'compose'];
    $environment = [];
    if ($conformance) {
        $command = [...$command, '--profile', 'conformance'];
        // A plan of a hundred requests has no use for a hundred profiles, and the toolbar has no place in
        // the pages the scripted browser of the suite reads.
        $environment['APP_PROFILER'] = '0';
    }
    if ($backend['profile'] !== null) {
        $command = [...$command, '--profile', $backend['profile']];
    }
    if ($accessTokenFormat !== null) {
        $environment['CONFORMANCE_ACCESS_TOKEN_FORMAT'] = $accessTokenFormat;
    }
    $command = [...$command, 'up', '-d', '--remove-orphans', '--wait'];
    if ($build) {
        $command[] = '--build';
    }
    run($command, context: context()->withEnvironment($environment));
    $started = match ($kms) {
        'vault' => ', Vault: http://localhost:8200 (dev mode, root token in compose.yaml); "castor provision --kms vault" seals the signing keys with it',
        'aws' => ', Floci (AWS KMS): http://localhost:4566 (credentials test/test, region eu-west-3); "castor provision --kms aws" seals the signing keys with it',
        default => '',
    };
    io()
        ->success('OP: https://op.localhost' . ($conformance ? ', conformance suite: https://localhost:8443, profiler off' : '') . ($accessTokenFormat === null ? '' : sprintf(', %s access tokens for the clients of the suite', $accessTokenFormat)) . $started);
}

/**
 * @return array{profile: ?string, scheme: string}
 */
function kms_backend(string $kms): array
{
    if (! isset(KMS_BACKENDS[$kms])) {
        io()->error(sprintf('Unknown KMS "%s"; the backends are %s.', $kms, implode(', ', array_keys(KMS_BACKENDS))));
        exit(1);
    }

    return KMS_BACKENDS[$kms];
}

/**
 * @return array<string>
 */
function compose_profiles(): array
{
    $options = [];
    foreach (COMPOSE_PROFILES as $profile) {
        $options[] = '--profile';
        $options[] = $profile;
    }

    return $options;
}

#[AsTask(description: 'Stop the development stack')]
function stop(): void
{
    run(['docker', 'compose', ...compose_profiles(), 'down', '--remove-orphans']);
}

#[AsTask(description: 'Follow the logs of the development stack', ignoreValidationErrors: true)]
function logs(#[AsRawTokens] array $args = []): void
{
    run(['docker', 'compose', ...compose_profiles(), 'logs', '-f', ...$args]);
}

#[AsTask(description: 'Run a Symfony console command of the application inside the op container', ignoreValidationErrors: true)]
function console(#[AsRawTokens] array $args = []): void
{
    op_console($args);
}

/**
 * Runs a console command of the application inside the op container, without a TTY when the input is
 * fed by the task (the password of the development user) or when the output is captured.
 *
 * @param array<string> $args
 */
function op_console(array $args, ?Context $context = null): Process
{
    $tty = $context === null && stream_isatty(\STDOUT);

    return run(
        ['docker', 'compose', 'exec', ...($tty ? [] : ['-T']), 'op', 'php', 'bin/console', ...$args],
        context: $context,
    );
}

#[AsTask(description: 'Build the stylesheet of the pages (Tailwind and DaisyUI) inside the op container; --watch rebuilds on change')]
function tailwind(bool $watch = false): void
{
    op_console(['tailwind:build', ...($watch ? ['--watch'] : [])]);
}
