<?php

declare(strict_types=1);

/*
 * The provisioning of the development stack: apps/op/.env.local, the tenant, the signing key, the user and
 * the client secrets, replayed on every run. What the CI runs after the stack is up.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Process\Process;

/**
 * The variables "castor provision" writes into apps/op/.env.local when they are missing: development
 * values, generated once per checkout, never committed (apps/op/.env explains each one).
 */
const DEV_ENV_LOCAL = 'apps/op/.env.local';

const DEV_USERNAME = 'alice';

/**
 * The slug of the one tenant of the development stack (apps/op/config/packages/heidi.yaml names no other,
 * HEIDI_TENANT_SLUG in compose.yaml is the same value for the KMS containers).
 */
const DEV_TENANT_SLUG = 'default';

/**
 * The description of the development user, every claim of OIDC Core §5.1 the "profile", "phone" and
 * "address" scopes stand for: the scope modules of the conformance plan check that UserInfo answers each
 * scope with its claims, and a user without them ends those modules in a warning (issue #45).
 */
const DEV_USER_PROFILE = [
    '--name', 'Alice Liddell',
    '--given-name', 'Alice',
    '--family-name', 'Liddell',
    '--middle-name', 'Pleasance',
    '--nickname', 'Ali',
    '--preferred-username', 'alice',
    '--profile-url', 'https://op.localhost/alice',
    '--picture', 'https://op.localhost/alice.png',
    '--website', 'https://op.localhost/',
    '--gender', 'female',
    '--birthdate', '1852-05-04',
    '--zoneinfo', 'Europe/London',
    '--locale', 'en-GB',
    '--phone-number', '+44 1865 000000',
    '--phone-number-verified',
    '--address', "1 Wonderland Road\nOxford OX1 1AA\nUnited Kingdom",
    '--street-address', '1 Wonderland Road',
    '--locality', 'Oxford',
    '--region', 'Oxfordshire',
    '--postal-code', 'OX1 1AA',
    '--country', 'United Kingdom',
];

const DEV_CLIENT_SECRETS = [
    'CONFORMANCE_BASIC_SECRET',
    'CONFORMANCE_BASIC_SECOND_SECRET',
    'CONFORMANCE_POST_SECRET',
    'CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET',
    'CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET',
    'OIDC_DEMO_SECRET',
];

#[AsTask(description: 'Provision the development OP after "castor start": the KMS that seals the signing keys and the secrets of the clients (apps/op/.env.local), then the tenant, a signing key (checked against the KMS when there is one already) and the user "alice" with a full profile and a password')]
function provision(
    #[AsOption(description: 'The KMS to seal the signing keys with when apps/op/.env.local names none yet: sodium (default, a key generated in place), file (the same key in a file of the op container, mode 0600), vault (a token minted under the policy of the OP on the Vault of "castor start --kms vault") or aws (the LocalStack of "castor start --kms aws"); the backend already there is kept, switching is a change of KMS')]
    ?string $kms = null,
): void {
    io()->title('Provisioning the development OP');

    io()
        ->section('Development secrets');
    $env = provision_env_local($kms);

    io()
        ->section('Tenant');
    op_console(['heidi:tenant:synchronize']);

    io()
        ->section('Signing key');
    // The console wraps its blocks: flatten before searching the sentence.
    $keys = (string) preg_replace('/\s+/', ' ', op_console(['heidi:keys:list'], context()->withQuiet())->getOutput());
    if (str_contains($keys, 'no published key')) {
        op_console(['heidi:keys:generate']);
    } else {
        // A key is published: before trusting it, ask the KMS to open it. Vault in dev mode and LocalStack
        // forget their master key when they restart, and the envelopes sealed under it are dead; the
        // command says which key and what to do, this task deletes nothing and stops here.
        $check = op_console(['heidi:keys:list', '--check'], context()->withAllowFailure());
        if (! $check->isSuccessful()) {
            io()->error(sprintf('The KMS of %s cannot open a published key (above). Run "castor console heidi:keys:rotate --now" once the KMS is back with its key, or with its new one, then this task again.', DEV_ENV_LOCAL));
            exit(1);
        }
        io()
            ->note('A signing key is published already and opens with the KMS; "castor console heidi:keys:rotate" rotates it without an outage.');
    }

    io()
        ->section(sprintf('User "%s"', DEV_USERNAME));
    $creation = op_console(
        ['heidi:user:create', DEV_USERNAME, '--email', DEV_USERNAME . '@op.localhost', '--email-verified'],
        context()
            ->withAllowFailure()
            ->withQuiet(),
    );
    if ($creation->isSuccessful()) {
        io()->write($creation->getOutput());
    } elseif (str_contains($creation->getOutput(), 'already exists')) {
        io()->note(sprintf('The user "%s" exists already; the password below is set again.', DEV_USERNAME));
    } else {
        io()->write($creation->getOutput());
        exit($creation->getExitCode() ?? 1);
    }
    // The whole profile of OIDC Core §5.1, so that every scope of the Basic OP plan gets its claims
    // (tests/conformance/README.md); replayed on every run, the command clears what it does not say.
    op_console(['heidi:user:profile', DEV_USERNAME, ...DEV_USER_PROFILE]);
    // Never on the command line: the command reads it on its standard input.
    op_console(
        ['heidi:user:set-password', DEV_USERNAME, '--password-stdin'],
        context()
            ->withInput($env['HEIDI_DEV_USER_PASSWORD'] . "\n"),
    );

    io()
        ->success('The OP is provisioned.');
    io()
        ->definitionList(
            [
                'Discovery' => $env['HEIDI_ISSUER'] . '/.well-known/openid-configuration',
            ],
            [
                'JWKS' => $env['HEIDI_ISSUER'] . '/jwks',
            ],
            [
                'KMS' => sprintf('%s, key %s', kms_backend_of($env['HEIDI_KMS_DSN']) ?? 'unknown', $env['HEIDI_KMS_KEY_ID']),
            ],
            [
                'Username' => DEV_USERNAME,
            ],
            [
                'Password' => $env['HEIDI_DEV_USER_PASSWORD'],
            ],
            ...array_map(static fn (string $name): array => [
                $name => $env[$name],
            ], DEV_CLIENT_SECRETS),
        );
    io()
        ->note(sprintf('These values live in %s; oidc-demo takes OIDC_DEMO_SECRET, "castor conformance" the others.', DEV_ENV_LOCAL));
}

/**
 * Writes the development values apps/op/.env.local lacks and returns the environment of the application
 * once they are loaded: the DSN of the KMS and the key it seals under (a sodium key generated in place or
 * written in a file of the op container, a token minted on the Vault of the stack under the policy of the
 * OP and the Transit key of the tenant, the LocalStack of the stack and the alias of the tenant), one
 * secret per client, the password of the development user. An existing value is kept, whoever wrote it:
 * the sealed signing keys depend on the KMS key, and a KMS is not switched by accident. The one exception
 * is a Vault token that no longer works (the dev server forgets everything when it restarts): a new one is
 * minted in its place, and the check of the published key says what became of the key files.
 *
 * @return array<string, string>
 */
function provision_env_local(?string $kms): array
{
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    $current = kms_backend_of($env['HEIDI_KMS_DSN'] ?? '');
    if ($current !== null && $kms !== null && $kms !== $current) {
        io()->error([
            sprintf('%s seals the signing keys with %s; "--kms %s" is a change of KMS, which this task never does by itself.', DEV_ENV_LOCAL, $current, $kms),
            sprintf('To switch: remove HEIDI_KMS_DSN and HEIDI_KMS_KEY_ID from %s, run this task again with "--kms %s", then "castor console heidi:keys:rotate --now": the envelopes sealed by %s cannot be opened by %s, the key that signed retires with its window and its public half still verifies what it signed; nothing is deleted.', DEV_ENV_LOCAL, $kms, $current, $kms),
        ]);
        exit(1);
    }
    $kms = $current ?? $kms ?? 'sodium';
    kms_backend($kms);

    $generate = static fn (int $bytes): string => rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    $values = match ($kms) {
        'sodium' => [
            'HEIDI_KMS_DSN' => static fn (): string => 'sodium://?keys[signing]=' . $generate(32),
            'HEIDI_KMS_KEY_ID' => static fn (): string => 'signing',
        ],
        // The same sodium backend reading <directory>/<key id><ext> (FilesystemKeyLoader): one file per
        // tenant, written in the container by this task, never in the checkout nor in the environment.
        'file' => [
            'HEIDI_KMS_DSN' => static fn (): string => 'sodium+dir://' . KMS_FILE_DIRECTORY . '?ext=.key',
            'HEIDI_KMS_KEY_ID' => static fn (): string => 'heidi-{tenant}',
        ],
        // The scheme and the options of the bridge (symfony/hashicorp-vault-key-management, README): the
        // token in the user component, the mount at its default, plain HTTP for the dev server.
        'vault' => [
            'HEIDI_KMS_DSN' => static fn (): string => 'hashicorp-vault-transit://' . vault_mint_op_token() . '@vault:8200?scheme=http',
            'HEIDI_KMS_KEY_ID' => static fn (): string => 'heidi-{tenant}',
        ],
        // The scheme and the options of the bridge (symfony/aws-key-management, README): the credential
        // pair in the user information, any host but "default" is a custom endpoint, plain HTTP for
        // LocalStack; the alias of the tenant is what docker/localstack/init.sh creates.
        'aws' => [
            'HEIDI_KMS_DSN' => static fn (): string => 'aws-kms://test:test@localstack:4566?region=eu-west-3&scheme=http',
            'HEIDI_KMS_KEY_ID' => static fn (): string => 'alias/heidi-{tenant}',
        ],
    };
    $values['HEIDI_DEV_USER_PASSWORD'] = static fn (): string => $generate(24);
    foreach (DEV_CLIENT_SECRETS as $name) {
        $values[$name] = static fn (): string => $generate(32);
    }

    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    if ($kms === 'file') {
        // Every run: a volume recreated with the stack has no key any more, and the check below says what
        // that did to the sealed keys; an existing key is kept.
        kms_file_write('heidi-' . DEV_TENANT_SLUG);
    }
    if ($current === 'vault' && ! vault_token_works(vault_token_of($env['HEIDI_KMS_DSN']))) {
        io()->warning(sprintf('The Vault token of %s no longer works (the dev server forgets its tokens and its keys when it restarts): a new one is minted. The keys sealed before the restart cannot be opened any more, which the check of the published key says below.', DEV_ENV_LOCAL));
        $env['HEIDI_KMS_DSN'] = $values['HEIDI_KMS_DSN']();
        file_put_contents($path, (string) preg_replace('/^HEIDI_KMS_DSN=.*$/m', sprintf('HEIDI_KMS_DSN="%s"', $env['HEIDI_KMS_DSN']), (string) file_get_contents($path)));
    }

    $lines = [];
    foreach ($values as $name => $value) {
        if (($env[$name] ?? '') !== '') {
            continue;
        }
        $env[$name] = $value();
        $lines[] = sprintf('%s="%s"', $name, $env[$name]);
    }
    if ($lines === []) {
        io()->note(sprintf('%s carries every development value already.', DEV_ENV_LOCAL));

        return $env;
    }

    $existing = file_exists($path) ? rtrim((string) file_get_contents($path), "\n") . "\n\n" : '';
    file_put_contents($path, $existing . "###> castor provision ###\n" . implode("\n", $lines) . "\n###< castor provision ###\n");
    io()
        ->text(sprintf('Wrote %d development value(s) into %s.', count($lines), DEV_ENV_LOCAL));

    return $env;
}

/**
 * The backend a KMS DSN names, by its scheme, or null when there is no DSN.
 */
function kms_backend_of(string $dsn): ?string
{
    if ($dsn === '') {
        return null;
    }
    foreach (KMS_BACKENDS as $name => $backend) {
        if (str_starts_with($dsn, $backend['scheme'] . '://')) {
            return $name;
        }
    }

    return null;
}

/**
 * Writes the key of the file backend in the op container, where the volume kms_data of compose.yaml holds
 * it for the worker too: 32 bytes of the kernel's randomness, mode 0600 in a directory 0700, the exact
 * length the sodium backend wants and nothing else in the file (FilesystemKeyLoader reads it verbatim). A
 * key that exists is kept: the sealed keys depend on it.
 */
function kms_file_write(string $name): void
{
    $path = sprintf('%s/%s.key', KMS_FILE_DIRECTORY, $name);
    $written = run(
        ['docker', 'compose', 'exec', '-T', 'op', 'sh', '-c', sprintf('umask 077 && mkdir -p %1$s && chmod 700 %1$s && if [ -e %2$s ]; then echo kept; else head -c 32 /dev/urandom > %2$s && echo written; fi', KMS_FILE_DIRECTORY, $path)],
        context: context()
            ->withAllowFailure()
            ->withQuiet(),
    );
    if (! $written->isSuccessful()) {
        io()->error(['The key file could not be written in the op container: is the stack running? "castor start" starts it.', trim($written->getErrorOutput())]);
        exit(1);
    }
    io()
        ->text(sprintf('%s the key of the file backend, %s in the op container (volume kms_data, mode 0600).', trim($written->getOutput()) === 'kept' ? 'Kept' : 'Wrote', $path));
}

/**
 * The token of a Vault DSN: its user component.
 */
function vault_token_of(string $dsn): string
{
    $token = parse_url($dsn, \PHP_URL_USER);
    if (! is_string($token) || $token === '') {
        io()->error(sprintf('The Vault DSN of %s carries no token.', DEV_ENV_LOCAL));
        exit(1);
    }

    return $token;
}

/**
 * Mints the credential of the OP on the Vault of the stack: a token under the policy "heidi-op" written by
 * docker/vault/init.sh (data keys and decryption under the Transit keys of the tenants, the configuration
 * of those keys, nothing else), with the root token of the dev server, which never reaches the OP.
 */
function vault_mint_op_token(): string
{
    $minted = vault_cli(['token', 'create', '-policy=heidi-op', '-no-default-policy', '-display-name=heidi-op', '-format=json']);
    if (! $minted->isSuccessful()) {
        io()->error(['The token of the OP could not be minted: is Vault running? "castor start --kms vault" starts it and initialises it.', trim($minted->getErrorOutput())]);
        exit(1);
    }
    $token = json_decode($minted->getOutput(), true)['auth']['client_token'] ?? null;
    if (! is_string($token) || $token === '') {
        io()->error('Vault answered without a token.');
        exit(1);
    }
    io()
        ->text('Minted a token for the OP on Vault, under the policy "heidi-op".');

    return $token;
}

/**
 * Whether a token still opens a session on the Vault of the stack.
 */
function vault_token_works(string $token): bool
{
    return vault_cli(['token', 'lookup'], [
        'VAULT_TOKEN' => $token,
    ])->isSuccessful();
}

/**
 * Runs the Vault CLI inside the vault container, with the root token of the dev server unless another one
 * is given; the output is captured, never shown.
 *
 * @param array<string> $args
 * @param array<string, string> $environment
 */
function vault_cli(array $args, array $environment = []): Process
{
    $options = [];
    foreach ($environment as $name => $value) {
        $options[] = '-e';
        $options[] = $name . '=' . $value;
    }

    return run(
        ['docker', 'compose', 'exec', '-T', ...$options, 'vault', 'vault', ...$args],
        context: context()
            ->withAllowFailure()
            ->withQuiet(),
    );
}
