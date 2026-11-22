<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\io;
use function Castor\run;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

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
 * The volume kms_data of compose.yaml, outside the web root and apart from the sealed keys.
 */
const KMS_FILE_DIRECTORY = '/app/var/kms';

/**
 * The compose profiles a task that stops or reads the whole stack must name.
 */
const COMPOSE_PROFILES = ['conformance', 'vault', 'aws', 'saml-sp', 'saml-idp'];

/**
 * Published by docker/op/entrypoint.sh: a copy of the mkcert root, or a link to the root of Caddy's internal CA.
 */
const CADDY_ROOT_CERTIFICATE = '/data/beffroi/root.crt';

/**
 * Keyed by the compose.yaml variable that renames the name, if any; a name left out is not on the stack certificate.
 *
 * @var array<int|string, string>
 */
const STACK_HOSTS = [
    'SERVER_NAME' => 'op.localhost',
    'MTLS_SERVER_NAME' => 'mtls.op.localhost',
    'ADMINISTRATION_SERVER_NAME' => 'admin.op.localhost',
    'saml-sp.localhost',
    'saml-idp.localhost',
];

/**
 * Relative to the root of the repository; compose.yaml mounts it read-only in the op container.
 */
const STACK_CERTIFICATE_DIRECTORY = 'var/stack-certificate';

const STACK_CERTIFICATE_RENEWAL_DAYS = 30;

/**
 * Keyed by the container whose network namespace the sidecar joins to carry port 8443 of the suite.
 *
 * @var array<string, string>
 */
const REDIRECTOR_SERVICES = [
    'worker' => 'conformance-worker-redirector',
    'op' => 'conformance-op-redirector',
];

#[AsTask(
    description: 'Start the development stack: the OP on https://op.localhost and PostgreSQL. Add --conformance for the OpenID conformance suite on https://localhost:8443, without the profiler; --access-token-format opaque hands the clients of the suite opaque access tokens; --kms vault adds HashiCorp Vault, --kms aws adds Floci (AWS KMS), each sealing the signing keys once "castor provision --kms <backend>" ran; the row of the tenant is written from the configuration at every start',
)]
function start(
    bool $conformance = false,
    bool $build = false,
    #[AsOption(description: 'The access token shape of the clients of the conformance suite: jwt (default) or opaque; the plans must be green with either')]
    ?string $accessTokenFormat = null,
    #[AsOption(
        description: 'The KMS that seals the signing keys: sodium (default) or file (in the process, nothing to start), vault (HashiCorp Vault Transit, dev mode, initialised at every start by docker/vault/init.sh) or aws (the KMS of Floci, an AWS emulator, initialised at every start by docker/floci/init.sh)',
    )]
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
        // The scripted browser of the suite reads pages that must not carry the toolbar.
        $environment['APP_PROFILER'] = '0';
        // Named, not looked up: the op container starts before the suite does and would find nothing to trust.
        $environment['CONFORMANCE_NGINX_HOST'] = 'conformance-nginx';
    }
    if ($backend['profile'] !== null) {
        $command = [...$command, '--profile', $backend['profile']];
    }
    if ($accessTokenFormat !== null) {
        $environment['CONFORMANCE_ACCESS_TOKEN_FORMAT'] = $accessTokenFormat;
    }
    $certificate = stack_certificate();
    if ($certificate !== null) {
        $environment['BEFFROI_STACK_CERTIFICATE'] = $certificate;
        // Caddy reads the certificate when it starts: a new fingerprint makes compose recreate the op container.
        $environment['BEFFROI_STACK_CERTIFICATE_FINGERPRINT'] = stack_certificate_fingerprint($certificate);
    }
    // Created here, or Docker creates these mounted directories as root and the tasks cannot write into them.
    foreach (['var/saml-sp/metadata', 'var/saml-idp/metadata', CONFORMANCE_CAPTURES] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    $up = ['up', '-d', '--remove-orphans', '--wait'];
    if ($build) {
        $up[] = '--build';
    }
    $context = context()->withEnvironment($environment);
    $provisioned = stack_names_a_kms();
    if ($provisioned) {
        run([...$command, ...$up], context: $context);
    } else {
        // The worker cannot boot before "castor provision" names its KMS: "up --wait" would wait on it forever.
        run([...$command, ...$up, ...compose_services_but_the_worker($command, $context)], context: $context);
        run([...$command, 'create', ...($build ? ['--build'] : []), 'worker'], context: $context);
    }
    // Every page refuses to serve a tenant whose row differs from apps/beffroi/.env*, which a pull can change.
    $tenant = op_console(['beffroi:tenant:synchronize', '--no-ansi'], context()->withAllowFailure()->withQuiet());
    if (! $tenant->isSuccessful()) {
        io()->write($tenant->getOutput() . $tenant->getErrorOutput());
        exit($tenant->getExitCode() ?? 1);
    }
    $started = match ($kms) {
        'vault' => ', Vault: http://localhost:8200 (dev mode, root token in compose.yaml); "castor provision --kms vault" seals the signing keys with it',
        'aws'
            => ', Floci (AWS KMS): http://localhost:4566 (credentials test/test, region eu-west-3); "castor provision --kms aws" seals the signing keys with it',
        default => '',
    };
    io()->success(
        'OP: https://op.localhost'
        . ($certificate === null ? ' (internal CA of Caddy)' : ' (certificate of the mkcert CA of the machine)')
        . ($conformance ? ', conformance suite: https://localhost:8443, profiler off' : '')
        . ($accessTokenFormat === null ? '' : sprintf(', %s access tokens for the clients of the suite', $accessTokenFormat))
        . $started
        . ($provisioned ? '' : '; the worker starts with "castor provision", which names the KMS it needs'),
    );
}

function stack_names_a_kms(): bool
{
    $path = getcwd() . '/' . DEV_ENV_LOCAL;

    return is_file($path) && preg_match('/^BEFFROI_KMS_DSN="?[^"\s]/m', (string) file_get_contents($path)) === 1;
}

/**
 * Also leaves out the sidecar that joins the network namespace of the worker.
 *
 * @param list<string> $compose "docker compose" and its profiles
 *
 * @return list<string>
 */
function compose_services_but_the_worker(array $compose, Context $context): array
{
    $services = run([...$compose, 'config', '--services'], context: $context->withQuiet())->getOutput();

    return array_values(array_diff(explode("\n", trim($services)), ['worker', REDIRECTOR_SERVICES['worker']]));
}

/**
 * @return list<string>
 */
function stack_hosts(): array
{
    $hosts = [];
    foreach (STACK_HOSTS as $variable => $default) {
        $value = is_string($variable) ? getenv($variable) : false;
        $hosts[] = is_string($value) && $value !== '' ? $value : $default;
    }

    return $hosts;
}

function mkcert_caroot(): ?string
{
    $mkcert = new ExecutableFinder()->find('mkcert');
    if ($mkcert === null) {
        return null;
    }
    $caroot = run([$mkcert, '-CAROOT'], context: context()->withQuiet()->withAllowFailure());
    if (! $caroot->isSuccessful()) {
        return null;
    }
    $directory = trim($caroot->getOutput());
    if ($directory === '' || ! is_file($directory . '/rootCA.pem') || ! is_file($directory . '/rootCA-key.pem')) {
        return null;
    }

    return $directory;
}

/**
 * The key of the mkcert root never leaves the directory mkcert keeps it in.
 */
function stack_certificate(): ?string
{
    $caroot = mkcert_caroot();
    if ($caroot === null) {
        return null;
    }
    $directory = context()->workingDirectory . '/' . STACK_CERTIFICATE_DIRECTORY;
    $hosts = stack_hosts();
    if (stack_certificate_is_current($directory, $hosts, $caroot . '/rootCA.pem')) {
        return $directory;
    }
    if (! is_dir($directory) && ! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }
    run(
        [
            'mkcert',
            '-cert-file',
            $directory . '/cert.pem',
            '-key-file',
            $directory . '/key.pem',
            ...$hosts,
        ],
        context: context()->withQuiet(),
    );
    if (! copy($caroot . '/rootCA.pem', $directory . '/root.pem')) {
        io()->error(sprintf('Cannot copy the mkcert root to %s.', $directory));
        exit(1);
    }
    io()->note(sprintf('The certificate of the stack was issued by mkcert for %s.', implode(', ', $hosts)));

    return $directory;
}

function stack_certificate_fingerprint(string $directory): string
{
    $certificate = file_get_contents($directory . '/cert.pem');
    $fingerprint = $certificate === false ? false : openssl_x509_fingerprint($certificate, 'sha256');
    if ($fingerprint === false) {
        io()->error(sprintf('Cannot read the certificate of the stack in %s.', $directory));
        exit(1);
    }

    return $fingerprint;
}

/**
 * @param list<string> $hosts
 */
function stack_certificate_is_current(string $directory, array $hosts, string $root): bool
{
    $certificate = @file_get_contents($directory . '/cert.pem');
    $copy = @file_get_contents($directory . '/root.pem');
    if ($certificate === false || $copy === false || ! is_file($directory . '/key.pem') || $copy !== file_get_contents($root)) {
        return false;
    }
    $parsed = openssl_x509_parse($certificate);
    if ($parsed === false || ! is_int($parsed['validTo_time_t'] ?? null)) {
        return false;
    }
    if ($parsed['validTo_time_t'] < (time() + (STACK_CERTIFICATE_RENEWAL_DAYS * 86_400))) {
        return false;
    }
    $alternativeNames = $parsed['extensions']['subjectAltName'] ?? null;
    if (! is_string($alternativeNames)) {
        return false;
    }
    $covered = array_map(static fn (string $name): string => trim(str_replace('DNS:', '', $name)), explode(',', $alternativeNames));
    $expected = $hosts;
    sort($covered);
    sort($expected);

    return $covered === $expected;
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

/**
 * @return array<string>
 */
function compose_running_services(): array
{
    $running = run(
        ['docker', 'compose', ...compose_profiles(), 'ps', '--status', 'running', '--services'],
        context: context()->withAllowFailure()->withQuiet(),
    );

    return $running->isSuccessful() ? explode("\n", trim($running->getOutput())) : [];
}

/**
 * Copies out of the op container the root of the certificate the stack serves: mkcert's or Caddy's internal one.
 */
function caddy_ca(string $destination): string
{
    $directory = dirname($destination);
    if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
        io()->error(sprintf('Cannot create %s.', $directory));
        exit(1);
    }
    if (! in_array('op', compose_running_services(), true)) {
        io()->error('The op container is not running, so there is no CA of Caddy to read: run "castor start" first.');
        exit(1);
    }
    $copy = run([
        'docker',
        'compose',
        'cp',
        '--follow-link',
        'op:' . CADDY_ROOT_CERTIFICATE,
        $destination,
    ], context: context()->withQuiet()->withAllowFailure());
    if (! $copy->isSuccessful() || ! is_file($destination)) {
        io()->error(sprintf(
            'Cannot read %s from the op container, which is running: "docker compose exec op ls %s" says what it holds.',
            CADDY_ROOT_CERTIFICATE,
            dirname(CADDY_ROOT_CERTIFICATE),
        ));
        exit(1);
    }

    return $destination;
}

/**
 * Recreated, never restarted, after the container it follows: a sidecar keeps the namespace it joined at creation.
 *
 * @param list<string> $restarted
 */
function compose_recreate_redirectors(array $restarted): void
{
    $running = compose_running_services();
    if (! in_array('conformance-nginx', $running, true)) {
        return;
    }
    foreach ($restarted as $container) {
        $sidecar = REDIRECTOR_SERVICES[$container] ?? null;
        if ($sidecar === null || ! in_array($container, $running, true)) {
            continue;
        }

        run(['docker', 'compose', ...compose_profiles(), 'up', '-d', '--force-recreate', '--no-deps', $sidecar]);
    }
}

/**
 * The op and worker processes keep the type registry they booted with, and read a retyped column with its old type.
 */
function compose_restart_after_migration(): void
{
    $running = compose_running_services();
    $restarted = array_values(array_filter(
        ['op', 'worker'],
        static fn (string $service): bool => in_array($service, $running, true),
    ));
    if ($restarted === []) {
        return;
    }

    io()->note(sprintf(
        'Restarting %s: a process that booted before a migration reads the columns it changed with the type they had.',
        implode(' and ', $restarted),
    ));
    run(['docker', 'compose', ...compose_profiles(), 'restart', ...$restarted]);
    // Last, and after the containers they follow, for the reason compose_recreate_redirectors gives.
    compose_recreate_redirectors($restarted);
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

#[AsTask(
    description: 'Run a Symfony console command of the application inside the op container; a migration restarts what reads the schema',
    ignoreValidationErrors: true,
)]
function console(#[AsRawTokens] array $args = []): void
{
    op_console($args);
    if (console_runs_the_migrations($args)) {
        compose_restart_after_migration();
    }
}

/**
 * Every token is scanned, not only the first non-option one, which may be the value of an option written apart.
 *
 * @param array<string> $args
 */
function console_runs_the_migrations(array $args): bool
{
    if (in_array('--dry-run', $args, true)) {
        return false;
    }
    return array_any($args, fn ($argument) => console_abbreviates($argument, 'doctrine:migrations:migrate'));
}

/**
 * Mirrors how Symfony\Component\Console\Application resolves an abbreviated command name.
 */
function console_abbreviates(string $token, string $command): bool
{
    $typed = explode(':', $token);
    $parts = explode(':', $command);
    if (count($typed) !== count($parts)) {
        return false;
    }
    return array_all($parts, fn ($part, $index) => ! ($typed[$index] === '' || ! str_starts_with($part, $typed[$index])));
}

/**
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
