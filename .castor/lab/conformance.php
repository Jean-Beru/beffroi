<?php

declare(strict_types=1);

/*
 * The OpenID conformance suite run against the stack (tests/conformance/README.md): a test of the OP, driven
 * through the API of the suite.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Console\Input\InputOption;

/**
 * The certification plans the OP answers (tests/conformance/README.md), by the short name "--plan" takes:
 * the name of each in the suite and the variants it is created with (the modules carry their own). One
 * configuration serves them all: the file whose {PLACEHOLDERS} the task fills from apps/op/.env.local,
 * and the values that must be there for the plans to make sense. An entry with "module" is not a plan
 * of the suite but one module run on its own, the suite having no plan for a single module; "before_start"
 * names what the task does between its creation and its start, in place of a human. "known" names the
 * modules the OP is known not to answer yet, each with its reason and the issue that closes it: their
 * result is reported as KNOWN and accepted, so that a gap we decided to leave open does not keep the CI
 * red for weeks, and the run fails the day one of them passes, so that the line is deleted rather than
 * carried. A module is listed there once the gap is written down, never to quiet a surprise.
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
    'form-post' => [
        'name' => 'oidcc-formpost-basic-certification-test-plan',
        'variant' => [
            'server_metadata' => 'discovery',
            'client_registration' => 'static_client',
        ],
        'known' => [
            'oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported' => 'the module writes response_mode only inside the request object, which the OP refuses unread (OIDC Core §6); heidi#142 closes it with JAR, spike 5',
        ],
    ],
    'rp-initiated-logout' => [
        'name' => 'oidcc-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
    ],
    // The one module of the Dynamic OP plan the OP answers, the judge of the key rotation (architecture
    // §3.3): it reads the JWK Set, waits for the operator to rotate the keys, reads it again and wants a
    // new key with the old one still there. The other plans of the suite are for response types and
    // features the OP does not have (implicit and hybrid, dynamic registration, back-channel and
    // front-channel logout, session management, third-party initiated login).
    'rotate-keys' => [
        'name' => 'oidcc-server-rotate-keys',
        'module' => true,
        'variant' => [
            'server_metadata' => 'discovery',
        ],
        'before_start' => 'rotate',
    ],
];

/**
 * The results no run of a plan can avoid and that a submission may be in (tests/conformance/README.md):
 * a module in one of them is never a gap of the OP, so it is never reported as known.
 */
const CONFORMANCE_UNCONDITIONALLY_ACCEPTED = ['PASSED', 'REVIEW', 'SKIPPED'];

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
 * How long the OP may take to serve its discovery document again after "--reset" restarted it.
 */
const CONFORMANCE_OP_TIMEOUT = 180;

/**
 * @param array<string> $plan
 * @param array<string> $module
 */
#[AsTask(description: 'Run the OpenID certification plans the OP answers (Basic OP, Config OP, Form Post OP, RP-Initiated Logout OP, and the key rotation module of the Dynamic OP plan) against it through the API of the suite started by "castor start --conformance", the scripted browser of the suite signing in as the development user and the task rotating the signing key when the suite asks for it, and print the result of every module')]
function conformance(
    #[AsOption(description: 'Run only this plan: basic, config, form-post, rp-initiated-logout or rotate-keys (repeatable); every plan by default', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $plan = [],
    #[AsOption(description: 'Run only the modules whose name contains this text (repeatable)', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $module = [],
    #[AsOption(description: 'Base URL of the suite; CONFORMANCE_TOKEN in the environment authenticates on a hosted one')]
    string $suite = 'https://localhost:8443',
    #[AsOption(description: 'Fail on WARNING as well as on FAILED, which is what the CI asks of the plans')]
    bool $strict = false,
    #[AsOption(description: 'Empty the database of the OP and provision it again before the plans run, which is the state they were written against: a development user with a password and nothing else')]
    bool $reset = false,
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
    if ($reset) {
        conformance_reset($env['HEIDI_ISSUER']);
    }

    $server = conformance_server($suite);
    io()
        ->text(sprintf('Suite %s (%s) on %s, OP %s', $server['version'] ?? '?', $server['tag'] ?? '?', $suite, $env['HEIDI_ISSUER']));
    $configuration = conformance_configuration($env);

    $rows = [];
    $verdict = [];
    $stale = [];
    $planUrls = [];
    foreach ($plans as $definition) {
        if ($definition['module'] ?? false) {
            $planId = null;
            $planUrl = null;
            $created = [
                'modules' => [
                    [
                        'testModule' => $definition['name'],
                        'variant' => $definition['variant'],
                    ],
                ],
            ];
        } else {
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
        }
        $modules = array_values(array_filter(
            $created['modules'],
            static fn (array $moduleDefinition): bool => $module === []
                || array_any($module, static fn (string $needle): bool => str_contains((string) $moduleDefinition['testModule'], $needle)),
        ));
        io()
            ->section($planId === null
                ? sprintf('%s: one module on its own, no plan', $definition['name'])
                : sprintf('%s: plan %s, %d module(s)', $definition['name'], $planId, count($modules)));
        if ($planUrl !== null) {
            io()
                ->text($planUrl);
        }
        if ($modules === []) {
            io()->warning(sprintf('No module of %s matches %s.', $definition['name'], implode(', ', $module)));
            continue;
        }

        foreach ($modules as $index => $moduleDefinition) {
            $name = (string) $moduleDefinition['testModule'];
            io()
                ->text(sprintf('[%d/%d] %s', $index + 1, count($modules), $name));
            $started = microtime(true);
            $run = conformance_run_module($suite, $planId, $moduleDefinition, $configuration, $definition['before_start'] ?? null);
            if ($planUrl === null) {
                $planUrls[] = sprintf('%s: %s', $name, $run['url']);
            }
            $elapsed = microtime(true) - $started;
            $known = $definition['known'][$name] ?? null;
            $result = $run['result'];
            if ($known !== null && ! in_array($result, CONFORMANCE_UNCONDITIONALLY_ACCEPTED, true)) {
                $result = 'KNOWN';
            }
            $rows[] = [$definition['name'], $name, $result, sprintf('%ds', (int) $elapsed), $run['url']];
            $verdict[$result] = ($verdict[$result] ?? 0) + 1;
            io()
                ->text(sprintf('  %s in %ds: %s', $result === 'KNOWN' ? sprintf('%s, known (%s)', $run['result'], $known) : $result, (int) $elapsed, $run['url']));
            foreach ($run['findings'] as $finding) {
                io()->text('    ' . $finding);
            }
            if ($known !== null && $result !== 'KNOWN') {
                $stale[] = sprintf('%s: %s (listed as known: %s)', $definition['name'], $name, $known);
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

    // A module listed as known that no longer fails is a line to delete, not a result to keep: the list
    // says what the OP cannot do yet, and it is wrong the moment it can.
    if ($stale !== []) {
        io()->error(['These modules no longer fail and must leave the "known" list of CONFORMANCE_PLANS:', ...$stale]);
        exit(1);
    }

    // WARNING and REVIEW are what a human reads before submitting; SKIPPED is the suite's own choice, and
    // KNOWN a gap named in CONFORMANCE_PLANS with the issue that closes it. Under --strict a WARNING is a
    // failure: the CI keeps the plans at the state a submission needs, and REVIEW and SKIPPED stay
    // accepted because no run of a plan can avoid them (tests/conformance/README.md).
    $accepted = $strict ? [...CONFORMANCE_UNCONDITIONALLY_ACCEPTED, 'KNOWN'] : [...CONFORMANCE_UNCONDITIONALLY_ACCEPTED, 'KNOWN', 'WARNING'];
    $failed = array_sum(array_filter($verdict, static fn (string $result): bool => ! in_array($result, $accepted, true), \ARRAY_FILTER_USE_KEY));
    if ($failed > 0) {
        io()->error(sprintf('%d module(s) did not pass.', $failed));
        exit(1);
    }
    $known = $verdict['KNOWN'] ?? 0;
    io()
        ->success($known === 0
            ? 'Every module passed.'
            : sprintf('Every module passed but %d left to a gap named in CONFORMANCE_PLANS.', $known));
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
 * Puts the OP back in the state the plans were written against: the tables dropped, the migrations of the
 * bundle replayed and "castor provision" run again, which leaves the development user with a password and
 * nothing else. A second factor or a passkey enrolled by hand (a run of "castor demo --passkey", an
 * afternoon on the account pages) stops the scripted browser of the suite on the page that asks for it,
 * and every module of every plan fails on the same line, "unexpected url for task: Verify complete". The
 * client secrets live in apps/op/.env.local and the clients in apps/op/config/packages/heidi.yaml, so
 * nothing of the configuration is lost; the signing keys are generated again, their sealed files in the
 * keys_data volume left behind as orphans.
 *
 * The containers are restarted at the end and the OP waited for: a worker of FrankenPHP holds the kernel
 * of the application for every request it serves, the opened signing key with it (architecture §3.3), and
 * a worker that was up before the tables went keeps a key no row names any more. It restarts on a source
 * change, never on a write in the database, so the reset restarts it.
 */
function conformance_reset(string $issuer): void
{
    io()
        ->section('Resetting the OP');
    op_console(['doctrine:schema:drop', '--full-database', '--force', '--no-interaction']);
    op_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);
    provision();
    run(['docker', 'compose', ...compose_profiles(), 'restart', 'op', 'worker']);
    conformance_wait_for_op($issuer);
}

/**
 * The OP, once it serves its discovery document again: "docker compose restart" returns before the
 * container is healthy, and a plan created in that window fails for nothing.
 */
function conformance_wait_for_op(string $issuer): void
{
    $deadline = microtime(true) + CONFORMANCE_OP_TIMEOUT;
    // The development OP is served by the internal CA of Caddy, which nothing on the host trusts.
    $url = $issuer . '/.well-known/openid-configuration';
    io()
        ->text(sprintf('Waiting for the OP on %s.', $url));
    while (true) {
        try {
            if (http_request('GET', $url, [
                'verify_peer' => false,
                'verify_host' => false,
            ])->getStatusCode() === 200) {
                return;
            }
        } catch (Throwable) {
        }
        if (microtime(true) >= $deadline) {
            io()->error(sprintf('The OP did not answer on %s within %d seconds after the reset.', $url, CONFORMANCE_OP_TIMEOUT));
            exit(1);
        }
        usleep(2_000_000);
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
 * Creates one module of the plan, or on its own with the configuration when there is no plan, starts it
 * when the suite waits for that, waits for it to finish while the scripted browser does the interaction,
 * and returns its result with the failures and warnings of its log. A module the browser cannot finish is
 * left to a human: the task prints the URLs the suite exposes and keeps waiting until
 * CONFORMANCE_MODULE_TIMEOUT. What the suite asks of the operator before the start ("Please rotate the
 * keys ... then press the 'Start' button") is $beforeStart, done by the task.
 *
 * @param array{testModule: string, variant?: array<string, string>} $definition
 * @return array{result: string, url: string, findings: array<string>}
 */
function conformance_run_module(string $suite, ?string $planId, array $definition, string $configuration = '', ?string $beforeStart = null): array
{
    $query = [
        'test' => $definition['testModule'],
    ];
    if ($planId !== null) {
        $query['plan'] = $planId;
    }
    if (($definition['variant'] ?? []) !== []) {
        $query['variant'] = json_encode($definition['variant'], \JSON_THROW_ON_ERROR);
    }
    $created = conformance_request($suite, 'POST', '/api/runner', [
        'query' => $query,
        // The configuration is the plan's, or the module's own when it has no plan; an empty POST must not
        // be declared as a form.
        'headers' => [
            'Content-Type' => 'application/json',
        ],
        ...($planId === null ? [
            'body' => $configuration,
        ] : []),
    ], 201);
    $id = (string) $created['id'];
    $url = sprintf('%s/log-detail.html?log=%s', $suite, $id);
    $deadline = microtime(true) + CONFORMANCE_MODULE_TIMEOUT;

    $state = conformance_wait_state($suite, $id, ['CONFIGURED', 'WAITING', 'FINISHED'], $deadline);
    if ($state === 'CONFIGURED') {
        if ($beforeStart === 'rotate') {
            conformance_rotate_signing_key();
        }
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
 * The rotation the key rotation module asks for, on the OP of the stack: the new key signs at once
 * (--now), the one that signed stays in the JWK Set for its retirement window, which is what the module
 * wants to see. The output of the command is shown: the two identifiers are what the log of the module
 * names.
 */
function conformance_rotate_signing_key(): void
{
    io()->text('  The suite asks for a rotation: "heidi:keys:rotate --now" on the OP.');
    $rotated = op_console(['heidi:keys:rotate', '--now', '--no-ansi'], context()->withAllowFailure()->withQuiet());
    if (! $rotated->isSuccessful()) {
        io()->error(['The signing key could not be rotated; the module will see no new key.', trim($rotated->getErrorOutput() . $rotated->getOutput())]);

        return;
    }
    foreach (preg_split('/\R/', trim($rotated->getOutput())) ?: [] as $line) {
        io()->text('  ' . $line);
    }
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
