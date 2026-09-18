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
        // The tests take longer than the 300 s composer allows a script by default; the runner decides when to stop.
        'COMPOSER_PROCESS_TIMEOUT' => '0',
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

#[AsTask(description: 'Run Infection for mutation testing, on the coverage produced by a fresh PHPUnit run. --diff keeps only the mutants of the lines added or modified since the base branch, the shape of every CI run; without it the whole source is mutated, which takes hours')]
function infect(
    int $minMsi = 0,
    int $minCoveredMsi = 0,
    #[AsOption(description: 'Mutate only the lines added or modified since --base, committed or not')]
    bool $diff = false,
    #[AsOption(description: 'The branch or commit the diff of --diff is taken from; Infection narrows it to the merge base with HEAD')]
    string $base = 'origin/main',
    #[AsOption(description: 'Mutant processes run in parallel; "max" is the number of cores minus one')]
    string $threads = 'max',
): void {
    // The XML coverage and the JUnit report of this run are what Infection reads from .ci-tools/coverage.
    phpunit();

    $options = [
        '--coverage=.ci-tools/coverage',
        '--skip-initial-tests',
        sprintf('--min-msi=%d', $minMsi),
        sprintf('--min-covered-msi=%d', $minCoveredMsi),
        '--threads=' . $threads,
        '--logger-github',
        '-s',
        // Each mutant runs only the test cases that cover its line (PHPUnit --filter), not the whole test files:
        // the functional tests cover most of the source, and the files they live in take minutes to run.
        // Infection still decides whether to skip a mutant from the summed duration of the covering test files
        // as reported by junit.xml, which is why the timeout of infection.json.dist is far above any single run.
        '--only-covering-test-cases',
    ];

    if ($diff) {
        // Infection runs "git diff <merge base> -- <source directories>" from the working directory and passes the
        // directories of infection.json.dist as they are written: this is why that file sits at the root of the
        // repository, not in .ci-tools with the other configurations. A diff that touches no source file is a success.
        $options[] = '--git-diff-lines';
        $options[] = '--git-diff-base=' . $base;
    }

    // The PHPUnit configuration Infection 0.32 generates still carries cacheResult="false", which PHPUnit 13
    // reports as a deprecation ("recordTestRunHistory" replaces it) and PHPUnit 14 will refuse.
    phpqa(['composer', 'exec', '--', 'infection', ...$options], [
        'XDEBUG_MODE' => 'coverage',
    ]);
}

#[AsTask(description: 'Start the development stack: the OP on https://op.localhost and PostgreSQL. Add --conformance for the OpenID conformance suite on https://localhost:8443, without the profiler; --access-token-format opaque hands the clients of the suite opaque access tokens')]
function start(
    bool $conformance = false,
    bool $build = false,
    #[AsOption(description: 'The access token shape of the clients of the conformance suite: jwt (default) or opaque; the plans must be green with either')]
    ?string $accessTokenFormat = null,
): void {
    if ($accessTokenFormat !== null && ! in_array($accessTokenFormat, ['jwt', 'opaque'], true)) {
        io()->error(sprintf('Unknown access token format "%s"; the formats are jwt and opaque.', $accessTokenFormat));
        exit(1);
    }
    $command = ['docker', 'compose'];
    $environment = [];
    if ($conformance) {
        $command = [...$command, '--profile', 'conformance'];
        // A plan of a hundred requests has no use for a hundred profiles, and the toolbar has no place in
        // the pages the scripted browser of the suite reads.
        $environment['APP_PROFILER'] = '0';
    }
    if ($accessTokenFormat !== null) {
        $environment['CONFORMANCE_ACCESS_TOKEN_FORMAT'] = $accessTokenFormat;
    }
    $command = [...$command, 'up', '-d', '--remove-orphans', '--wait'];
    if ($build) {
        $command[] = '--build';
    }
    run($command, context: context()->withEnvironment($environment));
    io()
        ->success('OP: https://op.localhost' . ($conformance ? ', conformance suite: https://localhost:8443, profiler off' : '') . ($accessTokenFormat === null ? '' : sprintf(', %s access tokens for the clients of the suite', $accessTokenFormat)));
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
 * The certification plans the OP answers (tests/conformance/README.md), by the short name "--plan" takes:
 * the name of each in the suite and the variants it is created with (the modules carry their own). One
 * configuration serves them all: the file whose {PLACEHOLDERS} the task fills from apps/op/.env.local,
 * and the values that must be there for the plans to make sense.
 */
const CONFORMANCE_PLANS = [
    'basic' => [
        'name' => 'oidcc-basic-certification-test-plan',
        'variant' => [
            'server_metadata' => 'discovery',
            'client_registration' => 'static_client',
        ],
    ],
    'config' => [
        'name' => 'oidcc-config-certification-test-plan',
        'variant' => [],
    ],
    'rp-initiated-logout' => [
        'name' => 'oidcc-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
    ],
];

const CONFORMANCE_CONFIGURATION = 'tests/conformance/configuration.json';

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
 * How long the suite may take to serve its API after its container reports healthy.
 */
const CONFORMANCE_SUITE_TIMEOUT = 180;

/**
 * @param array<string> $plan
 * @param array<string> $module
 */
#[AsTask(description: 'Run the OpenID certification plans the OP answers (Basic OP, Config OP, RP-Initiated Logout OP) against it through the API of the suite started by "castor start --conformance", the scripted browser of the suite signing in as the development user, and print the result of every module')]
function conformance(
    #[AsOption(description: 'Run only this plan: basic, config or rp-initiated-logout (repeatable); every plan by default', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $plan = [],
    #[AsOption(description: 'Run only the modules whose name contains this text (repeatable)', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $module = [],
    #[AsOption(description: 'Base URL of the suite; CONFORMANCE_TOKEN in the environment authenticates on a hosted one')]
    string $suite = 'https://localhost:8443',
    #[AsOption(description: 'Fail on WARNING as well as on FAILED, which is what the CI asks of the plans')]
    bool $strict = false,
): void {
    $unknown = array_diff($plan, array_keys(CONFORMANCE_PLANS));
    if ($unknown !== []) {
        io()->error(sprintf('Unknown plan %s; the plans are %s.', implode(', ', $unknown), implode(', ', array_keys(CONFORMANCE_PLANS))));
        exit(1);
    }
    $plans = $plan === [] ? CONFORMANCE_PLANS : array_intersect_key(CONFORMANCE_PLANS, array_flip($plan));
    io()
        ->title(sprintf('Conformance: %s', implode(', ', array_column($plans, 'name'))));

    $env = load_dot_env(getcwd() . '/apps/op/.env');
    $missing = array_filter(CONFORMANCE_REQUIRED_VALUES, static fn (string $name): bool => ($env[$name] ?? '') === '');
    if ($missing !== []) {
        io()->error(sprintf('%s: run "castor provision" first.', implode(', ', $missing) . ' missing from ' . DEV_ENV_LOCAL));
        exit(1);
    }

    $server = conformance_server($suite);
    io()
        ->text(sprintf('Suite %s (%s) on %s, OP %s', $server['version'] ?? '?', $server['tag'] ?? '?', $suite, $env['HEIDI_ISSUER']));
    $configuration = conformance_configuration($env);

    $rows = [];
    $verdict = [];
    $planUrls = [];
    foreach ($plans as $definition) {
        $created = conformance_request($suite, 'POST', '/api/plan', [
            'query' => [
                'planName' => $definition['name'],
                'variant' => json_encode((object) $definition['variant'], \JSON_THROW_ON_ERROR),
            ],
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => $configuration,
        ], 201);
        $planId = (string) $created['id'];
        $planUrl = sprintf('%s/plan-detail.html?plan=%s', $suite, $planId);
        $planUrls[] = sprintf('%s: %s', $definition['name'], $planUrl);
        $modules = array_values(array_filter(
            $created['modules'],
            static fn (array $moduleDefinition): bool => $module === []
                || array_any($module, static fn (string $needle): bool => str_contains((string) $moduleDefinition['testModule'], $needle)),
        ));
        io()
            ->section(sprintf('%s: plan %s, %d module(s)', $definition['name'], $planId, count($modules)));
        io()
            ->text($planUrl);
        if ($modules === []) {
            io()->warning(sprintf('No module of %s matches %s.', $definition['name'], implode(', ', $module)));
            continue;
        }

        foreach ($modules as $index => $moduleDefinition) {
            $name = (string) $moduleDefinition['testModule'];
            io()
                ->text(sprintf('[%d/%d] %s', $index + 1, count($modules), $name));
            $started = microtime(true);
            $run = conformance_run_module($suite, $planId, $moduleDefinition);
            $elapsed = microtime(true) - $started;
            $rows[] = [$definition['name'], $name, $run['result'], sprintf('%ds', (int) $elapsed), $run['url']];
            $verdict[$run['result']] = ($verdict[$run['result']] ?? 0) + 1;
            io()
                ->text(sprintf('  %s in %ds: %s', $run['result'], (int) $elapsed, $run['url']));
            foreach ($run['findings'] as $finding) {
                io()->text('    ' . $finding);
            }
        }
    }
    if ($rows === []) {
        io()->error(sprintf('No module of any plan matches %s.', implode(', ', $module)));
        exit(1);
    }

    io()
        ->newLine();
    io()
        ->table(['Plan', 'Module', 'Result', 'Time', 'Log'], $rows);
    io()
        ->text(sprintf('%d plan(s) on suite %s: %s', count($planUrls), $server['version'] ?? '?', implode(', ', array_map(
            static fn (string $result, int $count): string => sprintf('%d %s', $count, $result),
            array_keys($verdict),
            $verdict,
        ))));
    io()
        ->listing($planUrls);

    // WARNING and REVIEW are what a human reads before submitting; SKIPPED is the suite's own choice.
    // Under --strict a WARNING is a failure: the CI keeps the plans at the state a submission needs, and
    // REVIEW and SKIPPED stay accepted because no run of a plan can avoid them (tests/conformance/README.md).
    $accepted = $strict ? ['PASSED', 'REVIEW', 'SKIPPED'] : ['PASSED', 'WARNING', 'REVIEW', 'SKIPPED'];
    $failed = array_sum(array_filter($verdict, static fn (string $result): bool => ! in_array($result, $accepted, true), \ARRAY_FILTER_USE_KEY));
    if ($failed > 0) {
        io()->error(sprintf('%d module(s) did not pass.', $failed));
        exit(1);
    }
    io()
        ->success('Every module passed.');
}

/**
 * The suite, once it answers. Its container is healthy before its JVM serves the API, and nginx answers
 * 502 until then: a plan created in that window fails for nothing, which is the difference between a
 * developer who waits and a CI that does not.
 *
 * @return array<string, mixed>
 */
function conformance_server(string $suite): array
{
    $deadline = microtime(true) + CONFORMANCE_SUITE_TIMEOUT;
    $announced = false;
    while (true) {
        try {
            return conformance_request($suite, 'GET', '/api/server');
        } catch (Throwable $exception) {
            if (microtime(true) >= $deadline) {
                throw $exception;
            }
            if (! $announced) {
                io()->text(sprintf('Waiting for the suite on %s.', $suite));
                $announced = true;
            }
            usleep(2_000_000);
        }
    }
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

/**
 * oidc-demo, the reference client of the core (Symfony's oidc_login): where it is checked out, next to this
 * repository or next to the repository this one is nested in, where its server listens, and the client the
 * application registers for it (apps/op/config/packages/heidi.yaml).
 */
const DEMO_DIRS = ['../oidc-demo', '../../oidc-demo'];

const DEMO_URL = 'https://localhost:8002';

const DEMO_CLIENT_ID = 'oidc-demo';

#[AsTask(description: 'Point oidc-demo (Symfony oidc_login) at the development OP and start it on https://localhost:8002: its .env.local takes the issuer, the client and the secret of apps/op/.env.local, its php.ini trusts the CA of Caddy; --check then signs in as "alice", opens /profile and logs out from the command line')]
function demo(
    #[AsOption(description: 'Where oidc-demo is checked out; ../oidc-demo or ../../oidc-demo by default')]
    ?string $dir = null,
    #[AsOption(description: 'Sign in as the development user, open /profile and log out, from the command line, and print what was verified')]
    bool $check = false,
    #[AsOption(description: 'Stop the server of oidc-demo instead')]
    bool $stop = false,
): void {
    $isDemo = static fn (string $dir): bool => file_exists($dir . '/config/packages/security.yaml') && str_contains((string) file_get_contents($dir . '/config/packages/security.yaml'), 'oidc_login');
    $candidates = $dir === null ? DEMO_DIRS : [$dir];
    $dir = null;
    foreach ($candidates as $candidate) {
        $candidate = str_starts_with($candidate, '/') ? $candidate : getcwd() . '/' . $candidate;
        if ($isDemo($candidate)) {
            $dir = realpath($candidate) ?: $candidate;
            break;
        }
    }
    if ($dir === null) {
        io()->error(sprintf('oidc-demo is not in %s (no oidc_login firewall in config/packages/security.yaml). Pass --dir.', implode(' nor ', $candidates)));
        exit(1);
    }
    $server = context()
        ->withWorkingDirectory($dir);
    if ($stop) {
        run(['symfony', 'server:stop'], context: $server->withAllowFailure());

        return;
    }

    io()
        ->title('oidc-demo against the development OP');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['HEIDI_ISSUER', 'OIDC_DEMO_SECRET', 'HEIDI_DEV_USER_PASSWORD'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
            exit(1);
        }
    }

    io()
        ->section('Configuration');
    // .env.local only: the .env of the demo, which its repository holds, is not touched
    demo_write_env_local($dir . '/.env.local', [
        'OIDC_PROVIDER_URI' => $env['HEIDI_ISSUER'],
        'OIDC_CLIENT_ID' => DEMO_CLIENT_ID,
        'OIDC_CLIENT_SECRET' => $env['OIDC_DEMO_SECRET'],
    ]);
    // The OP serves a certificate of Caddy's internal CA, which the PHP of the host does not know unless
    // the CA was installed on the machine: the demo runs with a php.ini of its own that trusts it, which
    // the Symfony CLI reads from the root of the project.
    $ca = $dir . '/var/caddy-root.crt';
    if (! is_dir($dir . '/var')) {
        mkdir($dir . '/var', 0o777, true);
    }
    run(['docker', 'compose', 'cp', 'op:/data/caddy/pki/authorities/local/root.crt', $ca], context: context()->withQuiet());
    file_put_contents($dir . '/php.ini', sprintf("; written by \"castor demo\" of the OP: trust the CA of Caddy for https://op.localhost\nopenssl.cafile=%s\ncurl.cainfo=%s\n", $ca, $ca));
    io()
        ->text(sprintf('Issuer %s, client "%s", secret from apps/op/.env.local, CA of Caddy in %s.', $env['HEIDI_ISSUER'], DEMO_CLIENT_ID, $ca));

    io()
        ->section('Server');
    // the discovery document of the previous issuer may still be cached
    run(['php', 'bin/console', 'cache:clear'], context: $server->withQuiet());
    $status = run(['symfony', 'server:status'], context: $server->withAllowFailure()->withQuiet())->getOutput();
    if (str_contains($status, 'Listening on')) {
        io()->note('The server of oidc-demo runs already; "castor demo --stop" stops it.');
    } else {
        run(['symfony', 'server:start', '--port=' . parse_url(DEMO_URL, \PHP_URL_PORT), '--daemon'], context: $server);
    }
    io()
        ->success(sprintf('%s/profile signs in on %s as "%s", password %s.', DEMO_URL, $env['HEIDI_ISSUER'], DEV_USERNAME, $env['HEIDI_DEV_USER_PASSWORD']));

    if ($check) {
        demo_check($env['HEIDI_ISSUER'], $env['HEIDI_DEV_USER_PASSWORD'], $ca);
    }
}

/**
 * Sets or replaces the given variables in a dotenv file and keeps every other line.
 *
 * @param array<string, string> $values
 */
function demo_write_env_local(string $path, array $values): void
{
    $lines = file_exists($path) ? explode("\n", rtrim((string) file_get_contents($path), "\n")) : [];
    foreach ($values as $name => $value) {
        $line = sprintf('%s=%s', $name, $value);
        $written = false;
        foreach ($lines as $index => $existing) {
            if (str_starts_with($existing, $name . '=')) {
                $lines[$index] = $line;
                $written = true;
            }
        }
        if (! $written) {
            $lines[] = $line;
        }
    }
    file_put_contents($path, implode("\n", array_filter($lines, static fn (string $line): bool => $line !== '')) . "\n");
}

/**
 * The success criterion of spike 1, second half, from the command line: what a browser does from
 * /profile of the demo to the login page of the OP, the callback, /profile again and the logout, one
 * request at a time (no redirect followed), so that every step is looked at: PKCE S256 in the
 * authorization request, "iss" on the callback (RFC 9207), an "at+jwt" access token and an ID token with
 * the nonce on the page, the RP-Initiated Logout round trip, and no session left at the OP afterwards.
 */
function demo_check(string $issuer, string $password, string $ca): void
{
    io()
        ->section('Sign in, /profile, logout');
    $cookies = [];
    $verified = [];

    // /profile: the demo starts the flow
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), sprintf('/profile sends the browser to the authorization endpoint (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
    demo_expect(($authorization['response_type'] ?? null) === 'code' && ($authorization['code_challenge_method'] ?? null) === 'S256' && ($authorization['client_id'] ?? null) === DEMO_CLIENT_ID, 'the authorization request is response_type=code with PKCE S256');
    $verified[] = ['Authorization request', 'response_type=code, client_id=' . DEMO_CLIENT_ID . ', PKCE S256, nonce, state'];

    // the OP parks the request and asks for a login
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?interaction='), sprintf('the OP asks for a login (got %d %s)', $status, $location));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 200 && preg_match('/name="_csrf_token" value="([^"]+)"/', $page, $csrf) === 1 && preg_match('/action="([^"]+)"/', $page, $action) === 1, 'the login page carries the form');

    // the form, then the login page resumes the interaction and sends the browser back to the demo
    [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_username' => DEV_USERNAME,
        '_password' => $password,
        '_csrf_token' => $csrf[1],
    ]);
    demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, DEMO_URL . '/oidc/callback?'), sprintf('the OP sends the browser to the callback of the demo (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(isset($callback['code'], $callback['state']) && ($callback['iss'] ?? null) === $issuer, 'the callback carries code, state and iss (RFC 9207)');
    $verified[] = ['Authorization response', 'code, state, iss=' . $issuer];

    // the demo exchanges the code, reads UserInfo and opens /profile
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/profile', sprintf('the demo signs the user in (got %d %s)', $status, $location));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile opens (got %d)', $status));
    $tokens = demo_tokens_of($page);
    demo_expect(isset($tokens['id_token'], $tokens['access_token']), '/profile shows an ID token and an access token');
    $verified[] = ['/profile', sprintf('sub %s, %d claims from UserInfo', $tokens['id_token']['sub'] ?? '?', preg_match_all('/<tr><th>[a-z_]+<\/th>/', $page))];
    $verified[] = ['ID token', sprintf('nonce, auth_time, acr=%s, amr=%s, at_hash, sid', $tokens['id_token']['acr'] ?? '?', json_encode($tokens['id_token']['amr'] ?? null))];
    $verified[] = ['Access token', sprintf('typ=at+jwt, scope="%s", jti %s', $tokens['access_token']['scope'] ?? '?', $tokens['access_token']['jti'] ?? '?')];

    // RP-Initiated Logout: the demo ends its session and the one of the OP, which sends the browser back
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/logout');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/logout?'), sprintf('/logout sends the browser to the end session endpoint (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $logout);
    demo_expect(isset($logout['id_token_hint']) && ($logout['post_logout_redirect_uri'] ?? null) === DEMO_URL . '/', 'the logout request carries id_token_hint and post_logout_redirect_uri');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/', sprintf('the OP ends the session and sends the browser back to the demo (got %d %s)', $status, $location));
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), '/profile asks for a new login');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?'), 'the OP asks for a login again: its session ended');
    $verified[] = ['RP-Initiated Logout', 'id_token_hint verified, back to ' . DEMO_URL . '/, the OP asks for a login again'];

    io()
        ->table(['Step', 'Verified'], $verified);
    io()
        ->note(sprintf('The refresh of the access token (refresh_access_token) happens on the first request after it expired, ten minutes after the login (access_token_ttl of the application): sign in from a browser, open %s/profile again then and compare the "jti".', DEMO_URL));
    io()
        ->success('oidc-demo signed in, opened /profile and logged out against the OP, without a patch.');
}

/**
 * One request of the browser of the check, cookies kept per host, no redirect followed. The demo is a
 * development server with a certificate of the Symfony CLI, verified against nothing; the OP is verified
 * against the CA of Caddy.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @param array<string, string> $form
 * @return array{int, string, string} status, Location, body
 */
function demo_request(array &$cookies, string $ca, string $method, string $url, array $form = []): array
{
    $host = (string) parse_url($url, \PHP_URL_HOST);
    $options = [
        'max_redirects' => 0,
        'headers' => [
            'Cookie' => implode('; ', array_map(static fn (string $name, string $value): string => $name . '=' . $value, array_keys($cookies[$host] ?? []), array_values($cookies[$host] ?? []))),
        ],
    ];
    if ($host === 'localhost') {
        $options['verify_peer'] = false;
        $options['verify_host'] = false;
    } else {
        $options['cafile'] = $ca;
    }
    if ($form !== []) {
        $options['body'] = $form;
    }
    $response = http_request($method, $url, $options);
    $headers = $response->getHeaders(false);
    foreach ($headers['set-cookie'] ?? [] as $cookie) {
        [$pair] = explode(';', $cookie, 2);
        [$name, $value] = explode('=', $pair, 2) + [
            1 => '',
        ];
        $cookies[$host][trim($name)] = trim($value);
    }

    // a Location may be relative (RFC 9110 §10.2.2): resolved against the origin of the request
    $location = $headers['location'][0] ?? '';
    if (str_starts_with($location, '/')) {
        $port = parse_url($url, \PHP_URL_PORT);
        $location = sprintf('%s://%s%s%s', (string) parse_url($url, \PHP_URL_SCHEME), $host, $port === null ? '' : ':' . $port, $location);
    }

    return [$response->getStatusCode(), $location, $response->getContent(false)];
}

function demo_expect(bool $condition, string $what): void
{
    if (! $condition) {
        io()->error('Not verified: ' . $what);
        exit(1);
    }
    io()
        ->text(' <info>✓</info> ' . $what);
}

/**
 * The tokens the profile page prints in full, by their kind: the header "typ" tells the access token
 * (RFC 9068 §2.1), the "nonce" claim the ID token.
 *
 * @return array<string, array<string, mixed>>
 */
function demo_tokens_of(string $page): array
{
    $tokens = [];
    preg_match_all('/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/', $page, $matches);
    foreach (array_unique($matches[0]) as $jwt) {
        [$header, $payload] = explode('.', $jwt);
        $decode = static fn (string $part): array => (array) json_decode((string) base64_decode(strtr($part, '-_', '+/'), true), true);
        $header = $decode($header);
        $claims = $decode($payload);
        if (($header['typ'] ?? null) === 'at+jwt') {
            $tokens['access_token'] = $claims;
        } elseif (isset($claims['nonce'])) {
            $tokens['id_token'] = $claims;
        }
    }

    return $tokens;
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
