<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\guard_min_version;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Process\Process;

guard_min_version('v0.23.0');

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses.')]
function check_licenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0']
): void {
    io()->title('Checking licenses');
    $allowedExceptions = [];
    $command = ['composer', 'licenses', '-f', 'json'];
    $context = context();
    $context->withEnvironment([
        'XDEBUG_MODE' => 'off',
    ]);
    $context->withQuiet();
    $result = run($command, context: $context);
    if (! $result->isSuccessful()) {
        io()->error('Cannot determine licenses');
        exit(1);
    }
    $licenses = json_decode((string) $result->getOutput(), true);
    $disallowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => ! in_array($name, $allowedExceptions, true)
            && count(array_diff($info['license'], $allowedLicenses)) === 1,
        \ARRAY_FILTER_USE_BOTH
    );
    $allowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => in_array($name, $allowedExceptions, true)
            || count(array_diff($info['license'], $allowedLicenses)) === 0,
        \ARRAY_FILTER_USE_BOTH
    );
    if (count($disallowed) > 0) {
        io()->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                array_keys($disallowed),
                $disallowed
            )
        );
        io()
            ->error('Disallowed licenses found');
        exit(1);
    }
    io()
        ->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                array_keys($allowed),
                $allowed
            )
        );
    io()
        ->success('All licenses are allowed');
}

/**
 * Runs a command in the phpqa image, or directly when already inside a container (CI) or without Docker.
 * The environment applies in both cases.
 *
 * @param array<string> $command
 * @param array<string, string> $environment
 */
function phpqa(array $command, array $environment = []): void
{
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim(shell_exec('command -v docker') ?? '') !== '';
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;
    $environment += [
        'XDEBUG_MODE' => 'off',
    ];

    if (! $hasDocker || $inContainer) {
        run($command, context: context()->withEnvironment($environment));
        return;
    }

    if (! is_dir(getcwd() . '/tmp-phpqa')) {
        mkdir(getcwd() . '/tmp-phpqa');
    }

    $dockerOptions = [
        '--rm',
        '--init',
        stream_isatty(\STDOUT) ? '-it' : '-i',
        '--user', sprintf('%s:%s', getmyuid(), getmygid()),
        '-v', getcwd() . ':/project',
        '-v', getcwd() . '/tmp-phpqa:/project/tmp-phpqa',
        '-w', '/project',
        '-e', 'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d',
        '-e', 'PHP_INI_ENTRY=sys_temp_dir=/project/tmp-phpqa',
    ];
    foreach ($environment as $name => $value) {
        $dockerOptions[] = '-e';
        $dockerOptions[] = $name . '=' . $value;
    }

    run([
        'docker', 'run',
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', $phpVersion),
        ...$command,
    ]);
}

#[AsTask(description: 'Update the PHPQA Docker image')]
function phpqa_update(): void
{
    $phpVersion = getenv('PHP_VERSION') ?: (\PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION);

    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . $phpVersion]);
}

#[AsTask(description: 'Run PHPUnit tests with coverage', ignoreValidationErrors: true)]
function phpunit(#[AsRawTokens] array $args = []): void
{
    phpqa(
        [
            'composer', 'exec', '--', 'phpunit',
            '--coverage-xml', '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration', '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        [
            'XDEBUG_MODE' => 'coverage',
        ]
    );
}

#[AsTask(description: 'Run Easy Coding Standard')]
function ecs(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php']);
}

#[AsTask(description: 'Fix coding style with Easy Coding Standard')]
function ecs_fix(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php', '--fix']);
}

#[AsTask(description: 'Run Rector dry-run')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run PHPStan')]
function phpstan(): void
{
    phpqa([
        'composer', 'exec', '--', 'phpstan', 'analyse', '--error-format=github', '--configuration=.ci-tools/phpstan.neon',
    ]);
}

#[AsTask(description: 'Generate PHPStan baseline')]
function phpstan_baseline(): void
{
    phpqa([
        'composer', 'exec', '--', 'phpstan', 'analyse',
        '--configuration=.ci-tools/phpstan.neon',
        '--generate-baseline=.ci-tools/phpstan-baseline.neon',
        // A clean analysis is the expected outcome, not a failure of the task.
        '--allow-empty-baseline',
    ]);
}

#[AsTask(description: 'Run Deptrac')]
function deptrac(): void
{
    phpqa([
        'composer', 'exec', '--', 'deptrac',
        '--config-file', '.ci-tools/deptrac.yaml',
        '--report-uncovered',
        '--report-skipped',
        '--fail-on-uncovered',
    ]);
}

#[AsTask(description: 'Run PHP parallel linter')]
function lint(): void
{
    phpqa(['composer', 'exec', '--', 'parallel-lint', 'src', 'tests']);
}

#[AsTask(description: 'Run Infection for mutation testing, on the coverage produced by a fresh PHPUnit run')]
function infect(int $minMsi = 0, int $minCoveredMsi = 0): void
{
    // The XML coverage and the JUnit report of this run are what Infection reads from .ci-tools/coverage.
    phpunit();

    phpqa([
        'composer', 'exec', '--', 'infection',
        '--coverage=coverage',
        '--skip-initial-tests',
        sprintf('--min-msi=%d', $minMsi),
        sprintf('--min-covered-msi=%d', $minCoveredMsi),
        '--threads=max',
        '--logger-github',
        '-s',
        // Infection 0.32 generates a PHPUnit configuration with executionOrder="defects" and cacheResult="false";
        // PHPUnit 13 answers with a runner warning and, stopOnDefect being set too, executes no test at all.
        // Until Infection catches up, infection.json.dist points it at the PHPUnit 12 phar of the phpqa image.
        '--configuration=.ci-tools/infection.json.dist',
    ], [
        'XDEBUG_MODE' => 'coverage',
    ]);
}

#[AsTask(description: 'Start the development stack: the OP on https://op.localhost and PostgreSQL. Add --conformance for the OpenID conformance suite on https://localhost:8443')]
function start(bool $conformance = false, bool $build = false): void
{
    $command = ['docker', 'compose'];
    if ($conformance) {
        $command = [...$command, '--profile', 'conformance'];
    }
    $command = [...$command, 'up', '-d', '--remove-orphans', '--wait'];
    if ($build) {
        $command[] = '--build';
    }
    run($command);
    io()
        ->success('OP: https://op.localhost' . ($conformance ? ', conformance suite: https://localhost:8443' : ''));
}

#[AsTask(description: 'Stop the development stack')]
function stop(): void
{
    run(['docker', 'compose', '--profile', 'conformance', 'down', '--remove-orphans']);
}

#[AsTask(description: 'Follow the logs of the development stack', ignoreValidationErrors: true)]
function logs(#[AsRawTokens] array $args = []): void
{
    run(['docker', 'compose', '--profile', 'conformance', 'logs', '-f', ...$args]);
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

/**
 * The variables "castor provision" writes into apps/op/.env.local when they are missing: development
 * values, generated once per checkout, never committed (apps/op/.env explains each one).
 */
const DEV_ENV_LOCAL = 'apps/op/.env.local';

const DEV_USERNAME = 'alice';

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
    'OIDC_DEMO_SECRET',
];

#[AsTask(description: 'Provision the development OP after "castor start": the local KMS key and the secrets of the clients (apps/op/.env.local), then the tenant, a signing key and the user "alice" with a full profile and a password')]
function provision(): void
{
    io()->title('Provisioning the development OP');

    io()
        ->section('Development secrets');
    $env = provision_env_local();

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
        io()->note('A signing key is published already; "castor console heidi:keys:generate" rotates it.');
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
        ->note(sprintf('These values live in %s; oidc-demo takes OIDC_DEMO_SECRET, "castor conformance" the three others.', DEV_ENV_LOCAL));
}

/**
 * Writes the development values apps/op/.env.local lacks and returns the environment of the application
 * once they are loaded: a sodium key for the KMS, one secret per client, the password of the development
 * user. An existing value is kept, whoever wrote it: the sealed signing keys depend on the KMS key.
 *
 * @return array<string, string>
 */
function provision_env_local(): array
{
    $generate = static fn (int $bytes): string => rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    $values = [
        'HEIDI_KMS_DSN' => static fn (): string => 'sodium://?keys[signing]=' . $generate(32),
        'HEIDI_KMS_KEY_ID' => static fn (): string => 'signing',
        'HEIDI_DEV_USER_PASSWORD' => static fn (): string => $generate(24),
    ];
    foreach (DEV_CLIENT_SECRETS as $name) {
        $values[$name] = static fn (): string => $generate(32);
    }

    $env = load_dot_env(getcwd() . '/apps/op/.env');
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

    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    $existing = file_exists($path) ? rtrim((string) file_get_contents($path), "\n") . "\n\n" : '';
    file_put_contents($path, $existing . "###> castor provision ###\n" . implode("\n", $lines) . "\n###< castor provision ###\n");
    io()
        ->text(sprintf('Wrote %d development value(s) into %s.', count($lines), DEV_ENV_LOCAL));

    return $env;
}

/**
 * The conformance plan of spike 1 (tests/conformance/README.md): its name in the suite, the variants a plan
 * is created with (the modules carry their own), the configuration file whose {PLACEHOLDERS} the task fills
 * from apps/op/.env.local, and the values that must be there for the plan to make sense.
 */
const CONFORMANCE_PLAN = 'oidcc-basic-certification-test-plan';

const CONFORMANCE_PLAN_VARIANT = [
    'server_metadata' => 'discovery',
    'client_registration' => 'static_client',
];

const CONFORMANCE_CONFIGURATION = 'tests/conformance/basic-op.json';

const CONFORMANCE_REQUIRED_VALUES = [
    'HEIDI_ISSUER',
    'HEIDI_DEV_USER_PASSWORD',
    'CONFORMANCE_BASIC_SECRET',
    'CONFORMANCE_BASIC_SECOND_SECRET',
    'CONFORMANCE_POST_SECRET',
];

/**
 * How long a module may run before the task gives up on it, in seconds: the longest one waits thirty
 * seconds before reusing a code, and a module the scripted browser cannot finish waits for a human.
 */
const CONFORMANCE_MODULE_TIMEOUT = 300;

/**
 * @param array<string> $module
 */
#[AsTask(description: 'Run the OpenID conformance plan of spike 1 (Basic OP profile) against the OP through the API of the suite started by "castor start --conformance", the scripted browser of the suite signing in as the development user, and print the result of every module')]
function conformance(
    #[AsOption(description: 'Run only the modules whose name contains this text (repeatable)', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $module = [],
    #[AsOption(description: 'Base URL of the suite; CONFORMANCE_TOKEN in the environment authenticates on a hosted one')]
    string $suite = 'https://localhost:8443',
): void {
    io()->title(sprintf('Conformance: %s', CONFORMANCE_PLAN));

    $env = load_dot_env(getcwd() . '/apps/op/.env');
    $missing = array_filter(CONFORMANCE_REQUIRED_VALUES, static fn (string $name): bool => ($env[$name] ?? '') === '');
    if ($missing !== []) {
        io()->error(sprintf('%s: run "castor provision" first.', implode(', ', $missing) . ' missing from ' . DEV_ENV_LOCAL));
        exit(1);
    }

    $server = conformance_request($suite, 'GET', '/api/server');
    io()
        ->text(sprintf('Suite %s (%s) on %s, OP %s', $server['version'] ?? '?', $server['tag'] ?? '?', $suite, $env['HEIDI_ISSUER']));

    $plan = conformance_request($suite, 'POST', '/api/plan', [
        'query' => [
            'planName' => CONFORMANCE_PLAN,
            'variant' => json_encode(CONFORMANCE_PLAN_VARIANT, \JSON_THROW_ON_ERROR),
        ],
        'headers' => [
            'Content-Type' => 'application/json',
        ],
        'body' => conformance_configuration($env),
    ], 201);
    $planId = (string) $plan['id'];
    $planUrl = sprintf('%s/plan-detail.html?plan=%s', $suite, $planId);
    $modules = array_values(array_filter(
        $plan['modules'],
        static fn (array $definition): bool => $module === []
            || array_any($module, static fn (string $needle): bool => str_contains((string) $definition['testModule'], $needle)),
    ));
    if ($modules === []) {
        io()->error(sprintf('No module of the plan matches %s.', implode(', ', $module)));
        exit(1);
    }
    io()
        ->text(sprintf('Plan %s, %d module(s): %s', $planId, count($modules), $planUrl));

    $rows = [];
    $verdict = [];
    foreach ($modules as $index => $definition) {
        $name = (string) $definition['testModule'];
        io()
            ->section(sprintf('[%d/%d] %s', $index + 1, count($modules), $name));
        $started = microtime(true);
        $run = conformance_run_module($suite, $planId, $definition);
        $elapsed = microtime(true) - $started;
        $rows[] = [$name, $run['result'], sprintf('%ds', (int) $elapsed), $run['url']];
        $verdict[$run['result']] = ($verdict[$run['result']] ?? 0) + 1;
        io()
            ->text(sprintf('%s in %ds: %s', $run['result'], (int) $elapsed, $run['url']));
        foreach ($run['findings'] as $finding) {
            io()->text('  ' . $finding);
        }
    }

    io()
        ->newLine();
    io()
        ->table(['Module', 'Result', 'Time', 'Log'], $rows);
    io()
        ->text(sprintf('Plan %s on suite %s: %s', $planId, $server['version'] ?? '?', implode(', ', array_map(
            static fn (string $result, int $count): string => sprintf('%d %s', $count, $result),
            array_keys($verdict),
            $verdict,
        ))));
    io()
        ->text($planUrl);

    // WARNING and REVIEW are what a human reads before submitting; SKIPPED is the suite's own choice.
    $failed = array_sum(array_filter($verdict, static fn (string $result): bool => ! in_array($result, ['PASSED', 'WARNING', 'REVIEW', 'SKIPPED'], true), \ARRAY_FILTER_USE_KEY));
    if ($failed > 0) {
        io()->error(sprintf('%d module(s) did not pass.', $failed));
        exit(1);
    }
    io()
        ->success('Every module passed.');
}

/**
 * The plan configuration with its placeholders filled: {NAME} is the value of NAME in the environment of
 * the application, {HEIDI_DEV_USERNAME} the development user. The file itself carries no secret.
 *
 * @param array<string, string> $env
 */
function conformance_configuration(array $env): string
{
    $template = file_get_contents(getcwd() . '/' . CONFORMANCE_CONFIGURATION);
    if ($template === false) {
        throw new RuntimeException(sprintf('Cannot read %s.', CONFORMANCE_CONFIGURATION));
    }
    $values = [
        '{HEIDI_DEV_USERNAME}' => DEV_USERNAME,
    ];
    foreach ($env as $name => $value) {
        $values['{' . $name . '}'] = $value;
    }
    $configuration = strtr($template, $values);
    if (preg_match_all('/\{[A-Z][A-Z0-9_]*\}/', $configuration, $matches) > 0) {
        throw new RuntimeException(sprintf('%s: no value for %s.', CONFORMANCE_CONFIGURATION, implode(', ', array_unique($matches[0]))));
    }
    // Validates the JSON before the suite sees it.
    json_decode($configuration, flags: \JSON_THROW_ON_ERROR);

    return $configuration;
}

/**
 * Creates one module of the plan, starts it when the suite waits for that, waits for it to finish while
 * the scripted browser does the interaction, and returns its result with the failures and warnings of
 * its log. A module the browser cannot finish is left to a human: the task prints the URLs the suite
 * exposes and keeps waiting until CONFORMANCE_MODULE_TIMEOUT.
 *
 * @param array{testModule: string, variant?: array<string, string>} $definition
 * @return array{result: string, url: string, findings: array<string>}
 */
function conformance_run_module(string $suite, string $planId, array $definition): array
{
    $query = [
        'test' => $definition['testModule'],
        'plan' => $planId,
    ];
    if (($definition['variant'] ?? []) !== []) {
        $query['variant'] = json_encode($definition['variant'], \JSON_THROW_ON_ERROR);
    }
    $created = conformance_request($suite, 'POST', '/api/runner', [
        'query' => $query,
        // The configuration is the plan's; an empty POST must not be declared as a form.
        'headers' => [
            'Content-Type' => 'application/json',
        ],
    ], 201);
    $id = (string) $created['id'];
    $url = sprintf('%s/log-detail.html?log=%s', $suite, $id);
    $deadline = microtime(true) + CONFORMANCE_MODULE_TIMEOUT;

    $state = conformance_wait_state($suite, $id, ['CONFIGURED', 'WAITING', 'FINISHED'], $deadline);
    if ($state === 'CONFIGURED') {
        conformance_request($suite, 'POST', sprintf('/api/runner/%s', $id), [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
        ]);
        $state = conformance_wait_state($suite, $id, ['WAITING', 'FINISHED'], $deadline);
    }
    $announced = [];
    while ($state === 'WAITING') {
        $runner = conformance_request($suite, 'GET', sprintf('/api/runner/%s', $id));
        $pending = array_diff($runner['browser']['urls'] ?? [], $runner['browser']['visited'] ?? [], $announced);
        foreach ($pending as $pendingUrl) {
            io()->warning(sprintf('The suite waits for a browser on %s (see %s).', $pendingUrl, $url));
            $announced[] = $pendingUrl;
        }
        $state = conformance_wait_state($suite, $id, ['FINISHED'], $deadline);
    }

    $info = conformance_request($suite, 'GET', sprintf('/api/info/%s', $id));
    $result = (string) ($info['result'] ?? ($state === 'FINISHED' ? 'UNKNOWN' : $state));
    $findings = [];
    if ($result !== 'PASSED') {
        $log = conformance_request($suite, 'GET', sprintf('/api/log/%s', $id));
        foreach ($log as $entry) {
            if (! in_array($entry['result'] ?? null, ['FAILURE', 'WARNING', 'INTERRUPTED'], true)) {
                continue;
            }
            $message = (string) ($entry['msg'] ?? '');
            foreach (['error', 'error_description', 'detail'] as $key) {
                if (is_string($entry[$key] ?? null) && $entry[$key] !== '') {
                    $message .= sprintf(' [%s: %s]', $key, $entry[$key]);
                }
            }
            $findings[] = sprintf('%s %s: %s', $entry['result'], $entry['src'] ?? '?', $message);
        }
    }

    return [
        'result' => $result,
        'url' => $url,
        'findings' => $findings,
    ];
}

/**
 * Long-polls the state of a module until it is one of those wanted, or the deadline. An interrupted module
 * is returned as such: it is a result. Past the deadline the module is reported as TIMEOUT and left running.
 *
 * @param array<string> $states
 */
function conformance_wait_state(string $suite, string $id, array $states, float $deadline): string
{
    $states[] = 'INTERRUPTED';
    while (true) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) {
            return 'TIMEOUT';
        }
        $answer = conformance_request($suite, 'GET', sprintf('/api/runner/%s/wait-state', $id), [
            'query' => [
                'states' => implode(',', $states),
                'timeoutMs' => (string) min((int) ($remaining * 1000), 30000),
            ],
            'timeout' => 45,
        ]);
        if (($answer['timeout'] ?? false) === true || ! isset($answer['state'])) {
            continue;
        }

        return (string) $answer['state'];
    }
}

/**
 * One call to the API of the suite, decoded. The suite of "castor start --conformance" serves a self-signed
 * certificate for localhost and needs no token; a hosted suite has a public certificate and a token
 * (CONFORMANCE_TOKEN). Nothing here follows a redirect.
 *
 * @param array<string, mixed> $options
 * @return array<mixed>
 */
function conformance_request(string $suite, string $method, string $path, array $options = [], int $expected = 200): array
{
    $local = in_array(parse_url($suite, \PHP_URL_HOST), ['localhost', '127.0.0.1', '::1'], true);
    $token = getenv('CONFORMANCE_TOKEN') ?: null;
    $options['max_redirects'] = 0;
    $options['verify_peer'] = ! $local;
    $options['verify_host'] = ! $local;
    if ($token !== null) {
        $options['auth_bearer'] = $token;
    }

    $response = http_request($method, $suite . $path, $options);
    $status = $response->getStatusCode();
    $content = $response->getContent(false);
    if ($status !== $expected) {
        throw new RuntimeException(sprintf('%s %s answered %d: %s', $method, $path, $status, mb_substr($content, 0, 500)));
    }
    if ($content === '') {
        return [];
    }
    $decoded = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);

    return is_array($decoded) ? $decoded : [
        'value' => $decoded,
    ];
}

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis.')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    ecs_fix();
    rector_fix();

    io()
        ->section('Running static analysis…');
    phpstan_baseline();
    deptrac();
    lint();

    io()
        ->success('Code is ready. You may now commit and push your changes.');
}
