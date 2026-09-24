<?php

declare(strict_types=1);

/*
 * The quality tools, what the CI runs on every push (.github/workflows/ci.yml): each one in the phpqa image
 * when Docker is available.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses.')]
function check_licenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0'],
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
        static fn (array $info, $name) => ! in_array($name, $allowedExceptions, true) && count(array_diff($info['license'], $allowedLicenses)) === 1,
        \ARRAY_FILTER_USE_BOTH,
    );
    $allowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => in_array($name, $allowedExceptions, true) || count(array_diff($info['license'], $allowedLicenses)) === 0,
        \ARRAY_FILTER_USE_BOTH,
    );
    if (count($disallowed) > 0) {
        io()->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                array_keys($disallowed),
                $disallowed,
            ),
        );
        io()->error('Disallowed licenses found');
        exit(1);
    }
    io()->table(
        ['Package', 'License'],
        array_map(
            static fn ($name, $info) => [$name, implode(', ', $info['license'])],
            array_keys($allowed),
            $allowed,
        ),
    );
    io()->success('All licenses are allowed');
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
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-v',
        getcwd() . ':/project',
        '-v',
        getcwd() . '/tmp-phpqa:/project/tmp-phpqa',
        '-w',
        '/project',
        '-e',
        'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d',
        '-e',
        'PHP_INI_ENTRY=sys_temp_dir=/project/tmp-phpqa',
    ];
    foreach ($environment as $name => $value) {
        $dockerOptions[] = '-e';
        $dockerOptions[] = $name . '=' . $value;
    }

    run([
        'docker',
        'run',
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', $phpVersion),
        ...$command,
    ]);
}

#[AsTask(description: 'Update the PHPQA Docker image')]
function phpqa_update(): void
{
    $phpVersion = getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION;

    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . $phpVersion]);
}

#[AsTask(description: 'Run PHPUnit tests with coverage', ignoreValidationErrors: true)]
function phpunit(#[AsRawTokens] array $args = []): void
{
    phpqa(
        [
            'composer',
            'exec',
            '--',
            'phpunit',
            '--coverage-xml',
            '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        [
            'XDEBUG_MODE' => 'coverage',
        ],
    );
}

/*
 * Mago (https://mago.carthage.software/), the toolchain of Carthage Software: one Rust binary, no PHP
 * runtime, already installed in the phpqa image (/tools/mago), configured by mago.toml at the root of
 * the repository, which is where its editor integrations look for it. It holds the formatter and the
 * linter, in place of Easy Coding Standard. Its analyzer is not PHPStan's equal and replaces nothing:
 * see mago_analyze() below and the [analyzer] section of mago.toml.
 */

#[AsTask(description: 'Check the formatting with Mago')]
function mago_format(): void
{
    phpqa(['mago', 'format', '--check']);
}

#[AsTask(description: 'Format the code with Mago')]
function mago_format_fix(): void
{
    phpqa(['mago', 'format']);
}

#[AsTask(description: 'Run the Mago linter')]
function mago_lint(): void
{
    phpqa(['mago', 'lint']);
}

#[AsTask(description: 'Apply the fixes the Mago linter offers')]
function mago_lint_fix(): void
{
    phpqa(['mago', 'lint', '--fix']);
}

#[AsTask(description: 'Run the Mago analyzer. Informative only: PHPStan at level max is what the CI gates on, and the two do not find the same things')]
function mago_analyze(#[AsRawTokens] array $args = []): void
{
    phpqa(['mago', 'analyze', ...$args]);
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
        'composer',
        'exec',
        '--',
        'phpstan',
        'analyse',
        '--error-format=github',
        '--configuration=.ci-tools/phpstan.neon',
    ]);
}

#[AsTask(description: 'Generate PHPStan baseline')]
function phpstan_baseline(): void
{
    phpqa([
        'composer',
        'exec',
        '--',
        'phpstan',
        'analyse',
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
        'composer',
        'exec',
        '--',
        'deptrac',
        '--config-file',
        '.ci-tools/deptrac.yaml',
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

#[AsTask(
    description: 'Run Infection for mutation testing, on the coverage produced by a fresh PHPUnit run. --diff keeps only the mutants of the lines added or modified since the base branch, the shape of every CI run; without it the whole source is mutated, which takes hours',
)]
function infect(
    int $minMsi = 0,
    int $minCoveredMsi = 0,
    #[AsOption(description: 'Mutate only the lines added or modified since --base, committed or not')]
    bool $diff = false,
    #[AsOption(
        description: 'The branch or commit the diff of --diff is taken from; Infection narrows it to the merge base with HEAD. The default is the maintenance branch the clone points at, which a clone sets and "git remote set-head origin -a" restores',
    )]
    string $base = 'origin/HEAD',
    #[AsOption(description: 'Mutant processes run in parallel; "max" is the number of cores minus one')]
    string $threads = 'max',
    #[AsOption(
        description: 'Reuse the coverage of the last "castor phpunit" in .ci-tools/coverage instead of running the tests again; it must come from the same source and the same paths',
    )]
    bool $reuseCoverage = false,
): void {
    // The XML coverage and the JUnit report of a "castor phpunit" run are what Infection reads from .ci-tools/coverage.
    if ($reuseCoverage) {
        if (! is_file('.ci-tools/coverage/index.xml') || ! is_file('.ci-tools/coverage/junit.xml')) {
            io()->error('No coverage to reuse in .ci-tools/coverage: run "castor phpunit" first, or drop --reuse-coverage.');
            exit(1);
        }
    } else {
        phpunit();
    }

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

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis.')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    // The formatter runs last: Rector and the linter rewrite statements, the formatter lays them out.
    mago_lint_fix();
    rector_fix();
    mago_format_fix();

    io()->section('Running static analysis…');
    phpstan_baseline();
    deptrac();
    lint();

    io()->success('Code is ready. You may now commit and push your changes.');
}
