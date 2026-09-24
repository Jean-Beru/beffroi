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
 * the name of each in the suite and the variants it is created with (the modules carry their own). A plan
 * the suite has to be created twice with, once per set of variants, is two entries here and two runs:
 * the alias of the configuration is exclusive, so a run is a plan with its variants and nothing else.
 * One configuration serves them all: the file whose {PLACEHOLDERS} the task fills from
 * apps/op/.env.local, and the values that must be there for the plans to make sense. An entry with "module" is not a plan
 * of the suite but one module run on its own, the suite having no plan for a single module; "before_start"
 * names what the task does between its creation and its start, in place of a human. "known" names the
 * modules a run does not get past, each with its reason and the issue that closes it, whether the gap is
 * the provider's or a check of the suite behind the specifications the provider follows: their result is
 * reported as KNOWN and accepted, so that a gap we decided to leave open does not keep the CI red for
 * weeks, and the run fails the day one of them passes, so that the line is deleted rather than carried.
 * A module is listed there once the gap is written down, never to quiet a surprise.
 */
/**
 * A client per logout channel, in place of the "client" of the configuration: the suite certifies one
 * channel at a time and a module fails on a request to the endpoint of the other one, so the client of a
 * plan registers the URI of its channel and of no other (apps/op/config/packages/heidi.yaml).
 */
const CONFORMANCE_FRONT_CHANNEL_CLIENT = [
    'client_id' => 'conformance-front-channel-logout',
    'client_secret' => '{CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET}',
];

const CONFORMANCE_BACK_CHANNEL_CLIENT = [
    'client_id' => 'conformance-back-channel-logout',
    'client_secret' => '{CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET}',
];

/**
 * The clients of the FAPI 2 plans, in the order the suite names them: "client" and "client2", the second
 * one being what a module that presents an authorization code or a request URI issued to another client
 * uses. Two per pair, because a client authenticates with the one method it registered (RFC 6749 §2.3.1)
 * and the two pairs do not authenticate the same way. "castor provision" generates their keys into
 * var/conformance/ and publishes the public half to the provider
 * (apps/op/config/packages/heidi.yaml).
 */
const CONFORMANCE_FAPI_PRIVATE_KEY_JWT_CLIENTS = ['conformance-fapi-private-key-jwt', 'conformance-fapi-private-key-jwt-second'];

const CONFORMANCE_FAPI_MTLS_CLIENTS = ['conformance-fapi-mtls', 'conformance-fapi-mtls-second'];

/**
 * Message Signing runs with clients of its own: a client of those runs is registered to start every
 * authorization request with a request object it signed (OIDC Registration,
 * require_signed_request_object), which the unsigned requests of the Security Profile plan could not be.
 */
const CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_CLIENTS = ['conformance-fapi-signing-private-key-jwt', 'conformance-fapi-signing-private-key-jwt-second'];

const CONFORMANCE_FAPI_SIGNING_MTLS_CLIENTS = ['conformance-fapi-signing-mtls', 'conformance-fapi-signing-mtls-second'];

/**
 * The modules that need the user to have consented to nothing. A consent is remembered, which is what
 * makes the provider ask once and not at every authorization; a module that has to see the user refuse
 * needs the page where refusing happens, and an earlier module of the same plan has already granted it.
 * The consent is taken back before those modules and before no other, because taking it back before
 * every one of them would add a console call per module for nothing.
 */
const CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT = ['fapi2-security-profile-final-user-rejects-authentication'];

/**
 * Where "castor provision" left the key material of those clients, relative to the checkout.
 */
const CONFORMANCE_FAPI_DIRECTORY = 'var/conformance';

/**
 * What the FAPI clients ask for, in the order a module that reorders them will read it back: more than
 * one scope, so that the order can be changed, and the claims of the development user behind them.
 */
const CONFORMANCE_FAPI_SCOPE = 'openid profile email offline_access';

/**
 * The JWS algorithm the FAPI clients sign a DPoP proof with. ES256 is what their keys are
 * (var/conformance/), and RS256 is what the profile refuses.
 */
const CONFORMANCE_FAPI_DPOP_ALGORITHM = 'ES256';

/**
 * The resource a FAPI module calls with the access token it obtained: the UserInfo endpoint of the
 * provider, which is the protected resource an OpenID Provider serves (OIDC Core §5.3). Under the
 * ordinary origin for a token bound to a key, under the mTLS origin for one bound to a certificate
 * (RFC 8705 §5), since a bound token is presented on the connection it was bound on.
 */
const CONFORMANCE_FAPI_RESOURCE_PATH = '/userinfo';

/**
 * The one module the four FAPI 2 runs do not pass, the same one each time (issue #210). It reads the ID
 * token of a request carrying a "claims" parameter and warns on every claim it does not know; the one it
 * does not know is "sid", which names the session the token was issued in. An OP that announces
 * frontchannel_logout_session_supported or backchannel_logout_session_supported puts "sid" in the ID
 * tokens it issues (Front-Channel Logout 1.0 §3, Back-Channel Logout 1.0 §2.1), and this one announces
 * both as soon as it serves the channel; the claim is registered in the IANA "JSON Web Token Claims"
 * registry by Front-Channel Logout 1.0 §6.1.1. The list of the suite (ValidateIdTokenStandardClaims)
 * does not carry it, so the module is a check behind its own specifications and not a gap of the
 * provider: dropping the claim would contradict the metadata the provider publishes and would take from
 * the logout endpoint what tells it the hint describes the session in front of it (architecture §4.9).
 */
const CONFORMANCE_FAPI_KNOWN_MODULES = [
    'fapi2-security-profile-final-test-claims-parameter-identity-claims' => 'the ID token carries "sid", a claim Front-Channel Logout 1.0 §3 defines and the suite does not know; heidi#210',
];

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
    ],
    'rp-initiated-logout' => [
        'name' => 'oidcc-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
    ],
    // Each logout channel is certified with a client of its own, and neither with the client the other
    // plans use: a client that registers a logout URI is told at every logout of its sessions, and a
    // module of another plan fails on a request it did not expect ("Got an HTTP request to
    // 'frontchannel_logout' that wasn't expected"). That is the metadata working as written, per client,
    // and it is why certifying the three logout profiles takes three clients.
    'front-channel-logout' => [
        'name' => 'oidcc-frontchannel-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
        'client' => CONFORMANCE_FRONT_CHANNEL_CLIENT,
    ],
    // The one plan whose modules the OP answers from outside the browser: the worker posts the logout
    // token to the URI the suite gives its clients, which names localhost:8443 and is the suite itself
    // from the host. Inside the worker that address is the worker, so the conformance-worker-redirector
    // sidecar of compose.yaml brings the port there, and the entrypoint of the worker trusts the
    // certificate nginx answers with (docker/worker/entrypoint.sh). The module waits for the token while
    // it runs, which makes the latency of the worker a matter of conformance and not of operations.
    'back-channel-logout' => [
        'name' => 'oidcc-backchannel-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
        'client' => CONFORMANCE_BACK_CHANNEL_CLIENT,
    ],
    // The four runs of FAPI 2 (issue #166), the judge of spike 5: two profiles, and each of them once
    // per pair the profile lets an authorization server choose between, because a plan created with
    // variants is a run of its own and the alias of the configuration makes runs exclusive. The pair is
    // always read the same way round: "private_key_jwt" proves a key and DPoP binds the token to a key,
    // "mtls" proves a certificate and the same certificate binds the token, and nothing here mixes the
    // two. The clients are named per pair, and the sender constraining of the variant is what says
    // whether the suite presents a certificate and on which host it calls the resource.
    'fapi2-security-dpop' => [
        'name' => 'fapi2-security-profile-final-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'sender_constrain' => 'dpop',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_PRIVATE_KEY_JWT_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    'fapi2-security-mtls' => [
        'name' => 'fapi2-security-profile-final-test-plan',
        'variant' => [
            'client_auth_type' => 'mtls',
            'sender_constrain' => 'mtls',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_MTLS_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    // The same two pairs, with the request signed and the answer signed: what Message Signing adds to
    // the Security Profile (FAPI 2.0 Message Signing §5.3.1, JARM).
    'fapi2-signing-dpop' => [
        'name' => 'fapi2-message-signing-final-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'sender_constrain' => 'dpop',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
            'fapi_request_method' => 'signed_non_repudiation',
            'fapi_response_mode' => 'jarm',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    'fapi2-signing-mtls' => [
        'name' => 'fapi2-message-signing-final-test-plan',
        'variant' => [
            'client_auth_type' => 'mtls',
            'sender_constrain' => 'mtls',
            'openid' => 'openid_connect',
            'fapi_profile' => 'plain_fapi',
            'authorization_request_type' => 'simple',
            'fapi_request_method' => 'signed_non_repudiation',
            'fapi_response_mode' => 'jarm',
        ],
        'fapi' => [
            'clients' => CONFORMANCE_FAPI_SIGNING_MTLS_CLIENTS,
        ],
        'known' => CONFORMANCE_FAPI_KNOWN_MODULES,
    ],
    // The one module of the Dynamic OP plan the OP answers, the judge of the key rotation (architecture
    // §3.3): it reads the JWK Set, waits for the operator to rotate the keys, reads it again and wants a
    // new key with the old one still there. The other plans of the suite are for response types and
    // features the OP does not have (implicit and hybrid, dynamic registration, session management,
    // third-party initiated login).
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
    // The host whose listener asks for a client certificate, where the FAPI runs that bind their tokens
    // to one call the token, the PAR and the resource endpoints (RFC 8705 §5).
    'HEIDI_MTLS_ORIGIN',
    'HEIDI_DEV_USER_PASSWORD',
    'CONFORMANCE_BASIC_SECRET',
    'CONFORMANCE_BASIC_SECOND_SECRET',
    'CONFORMANCE_POST_SECRET',
    'CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET',
    'CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET',
];

/**
 * How long a module may run before the task gives up on it, in seconds: the longest one waits thirty
 * seconds before reusing a code, and a module the scripted browser cannot finish waits for a human.
 */
const CONFORMANCE_MODULE_TIMEOUT = 300;

/**
 * How long a module is given to leave CONFIGURED before the start is asked for a second time, seconds.
 */
const CONFORMANCE_START_CONFIRMATION = 15;

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
#[AsTask(
    description: 'Run the certification plans the OP answers (Basic OP, Config OP, Form Post OP, the three logout profiles, the four runs of FAPI 2 and the key rotation module of the Dynamic OP plan) against it through the API of the suite started by "castor start --conformance", the scripted browser of the suite signing in as the development user and the task rotating the signing key when the suite asks for it, and print the result of every module',
)]
function conformance(
    #[AsOption(
        description: 'Run only this plan: basic, config, form-post, rp-initiated-logout, front-channel-logout, back-channel-logout, fapi2-security-dpop, fapi2-security-mtls, fapi2-signing-dpop, fapi2-signing-mtls or rotate-keys (repeatable); every plan by default',
        mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
    )]
    array $plan = [],
    #[AsOption(description: 'Run only the modules whose name contains this text (repeatable)', mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY)]
    array $module = [],
    #[AsOption(description: 'Base URL of the suite; CONFORMANCE_TOKEN in the environment authenticates on a hosted one')]
    string $suite = 'https://localhost:8443',
    #[AsOption(description: 'Fail on WARNING as well as on FAILED, which is what the CI asks of the plans')]
    bool $strict = false,
    #[AsOption(
        description: 'Empty the database of the OP and provision it again before the plans run, which is the state they were written against: a development user with a password and nothing else',
    )]
    bool $reset = false,
): void {
    $unknown = array_diff($plan, array_keys(CONFORMANCE_PLANS));
    if ($unknown !== []) {
        io()->error(sprintf('Unknown plan %s; the plans are %s.', implode(', ', $unknown), implode(', ', array_keys(CONFORMANCE_PLANS))));
        exit(1);
    }
    $plans = $plan === [] ? CONFORMANCE_PLANS : array_intersect_key(CONFORMANCE_PLANS, array_flip($plan));
    io()->title(sprintf('Conformance: %s', implode(', ', array_column($plans, 'name'))));

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
    io()->text(sprintf('Suite %s (%s) on %s, OP %s', $server['version'] ?? '?', $server['tag'] ?? '?', $suite, $env['HEIDI_ISSUER']));
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
            $configuration = conformance_configuration($env, $definition);
            $created = conformance_request(
                $suite,
                'POST',
                '/api/plan',
                [
                    'query' => [
                        'planName' => $definition['name'],
                        'variant' => json_encode((object) $definition['variant'], \JSON_THROW_ON_ERROR),
                    ],
                    'headers' => [
                        'Content-Type' => 'application/json',
                    ],
                    'body' => $configuration,
                ],
                201,
            );
            $planId = (string) $created['id'];
            $planUrl = sprintf('%s/plan-detail.html?plan=%s', $suite, $planId);
            $planUrls[] = sprintf('%s: %s', $definition['name'], $planUrl);
        }
        // What a plan runs by default, which naming a module with --module lifts: the restriction is
        // there to keep a run lean, never to stop an operator from asking for a module by its name.
        $only = $module === [] ? $definition['modules'] ?? [] : [];
        $modules = array_values(array_filter(
            $created['modules'],
            static fn (array $moduleDefinition): bool => (
                ($only === [] || in_array((string) $moduleDefinition['testModule'], $only, true))
                && ($module === [] || array_any($module, static fn (string $needle): bool => str_contains((string) $moduleDefinition['testModule'], $needle)))
            ),
        ));
        io()->section(
            $planId === null
                ? sprintf('%s: one module on its own, no plan', $definition['name'])
                : sprintf('%s: plan %s, %d module(s)', $definition['name'], $planId, count($modules)),
        );
        if ($planUrl !== null) {
            io()->text($planUrl);
        }
        if ($modules === []) {
            io()->warning(sprintf('No module of %s matches %s.', $definition['name'], implode(', ', $module)));
            continue;
        }

        foreach ($modules as $index => $moduleDefinition) {
            $name = (string) $moduleDefinition['testModule'];
            io()->text(sprintf('[%d/%d] %s', $index + 1, count($modules), $name));
            conformance_forget_consents($name, $definition['fapi']['clients'] ?? []);
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
            io()->text(sprintf(
                '  %s in %ds: %s',
                $result === 'KNOWN' ? sprintf('%s, known (%s)', $run['result'], $known) : $result,
                (int) $elapsed,
                $run['url'],
            ));
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

    io()->newLine();
    io()->table(['Plan', 'Module', 'Result', 'Time', 'Log'], $rows);
    io()->text(sprintf(
        '%d plan(s) on suite %s: %s',
        count($planUrls),
        $server['version'] ?? '?',
        implode(', ', array_map(
            static fn (string $result, int $count): string => sprintf('%d %s', $count, $result),
            array_keys($verdict),
            $verdict,
        )),
    ));
    io()->listing($planUrls);

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
    io()->success(
        $known === 0
            ? 'Every module passed.'
            : sprintf('Every module passed but %d left to a gap named in CONFORMANCE_PLANS.', $known),
    );
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
    io()->section('Resetting the OP');
    op_console(['doctrine:schema:drop', '--full-database', '--force', '--no-interaction']);
    op_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);
    provision();
    run(['docker', 'compose', ...compose_profiles(), 'restart', 'op', 'worker']);
    // Last, and after the worker, or the back-channel plan would wait for a token that cannot arrive.
    compose_recreate_worker_redirector();
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
    io()->text(sprintf('Waiting for the OP on %s.', $url));
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
 * the application, {HEIDI_DEV_USERNAME} the development user. The file itself carries no secret. A plan
 * that names a client of its own has the "client" of the file replaced before the placeholders are
 * filled, so that its secret comes from the environment like every other; a FAPI plan replaces the
 * clients and what goes with them, which is not in the file at all but in var/conformance/.
 *
 * @param array<string, string> $env
 * @param array<string, mixed> $definition the plan, as CONFORMANCE_PLANS declares it
 */
function conformance_configuration(array $env, array $definition): string
{
    $template = file_get_contents(getcwd() . '/' . CONFORMANCE_CONFIGURATION);
    if ($template === false) {
        throw new RuntimeException(sprintf('Cannot read %s.', CONFORMANCE_CONFIGURATION));
    }
    $client = $definition['client'] ?? [];
    $fapi = $definition['fapi'] ?? [];
    if ($client !== [] || $fapi !== []) {
        $decoded = json_decode($template, true, 32, \JSON_THROW_ON_ERROR);
        if ($client !== []) {
            $decoded['client'] = $client;
        }
        if ($fapi !== []) {
            $decoded = conformance_fapi_sections($decoded, $fapi['clients'], (string) $definition['variant']['sender_constrain']);
        }
        $template = json_encode($decoded, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT);
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
 * The sections a FAPI 2 plan needs in place of those the six OpenID Connect plans use: two clients that
 * prove a key or a certificate instead of a shared secret, what each one presents at the handshake when
 * the tokens are bound to a certificate, and the resource a module calls with the token it obtained. The
 * client that authenticates with a shared secret in the file has no place in a FAPI run, so it goes.
 *
 * @param array<string, mixed> $configuration
 * @param list<string> $clients the two clients of the run, "client" and "client2"
 * @param string $senderConstrain what the tokens of the run are bound to, "dpop" or "mtls"
 *
 * @return array<string, mixed>
 */
function conformance_fapi_sections(array $configuration, array $clients, string $senderConstrain): array
{
    unset($configuration['client_secret_post']);
    $certificates = $senderConstrain === 'mtls';
    foreach (['client', 'client2'] as $index => $section) {
        $configuration[$section] = conformance_fapi_client($clients[$index], $certificates);
        if ($certificates) {
            $configuration[$index === 0 ? 'mtls' : 'mtls2'] = conformance_fapi_certificate($clients[$index]);
        }
    }
    // A token bound to a certificate is presented on a connection that carries that certificate, so the
    // resource is called on the host whose listener asks for one (RFC 8705 §5); a token bound to a key
    // is presented anywhere, and the ordinary host of the provider is where the other plans call too.
    $configuration['resource'] = [
        'resourceUrl' => ($certificates ? '{HEIDI_MTLS_ORIGIN}' : '{HEIDI_ISSUER}') . CONFORMANCE_FAPI_RESOURCE_PATH,
    ];

    return $configuration;
}

/**
 * One client of a FAPI run: its identifier, the whole of the key "castor provision" generated for it,
 * private half included, since the suite is the client here, and what it asks for. A run that binds its
 * tokens to a key names the algorithm the proofs are signed with; one that binds them to a certificate
 * presents that certificate instead, and the key is still what signs a request object.
 *
 * @return array<string, mixed>
 */
function conformance_fapi_client(string $clientId, bool $certificates): array
{
    $client = [
        'client_id' => $clientId,
        'jwks' => conformance_fapi_material($clientId, 'jwks.json', static fn (string $contents): array => json_decode(
            $contents,
            true,
            8,
            \JSON_THROW_ON_ERROR,
        )),
        'scope' => CONFORMANCE_FAPI_SCOPE,
    ];
    if (! $certificates) {
        $client['dpop_signing_alg'] = CONFORMANCE_FAPI_DPOP_ALGORITHM;
    }

    return $client;
}

/**
 * The certificate one client of a FAPI run presents at the handshake, with its key: the self-signed pair
 * of var/conformance/, which the provider authenticates against the "x5c" the client publishes (RFC 8705
 * §2.2). There is no chain and no authority, so the suite is given none.
 *
 * @return array<string, string>
 */
function conformance_fapi_certificate(string $clientId): array
{
    return [
        'cert' => conformance_fapi_material($clientId, 'crt', static fn (string $contents): string => $contents),
        'key' => conformance_fapi_material($clientId, 'key', static fn (string $contents): string => $contents),
    ];
}

/**
 * One file of var/conformance/, read as what it is. A file that is not there is a stack that was never
 * provisioned, or one provisioned before the FAPI clients existed: the task says so rather than creating
 * a plan the suite would fail on.
 *
 * @template T
 *
 * @param callable(string): T $read
 *
 * @return T
 */
function conformance_fapi_material(string $clientId, string $extension, callable $read): mixed
{
    $path = sprintf('%s/%s/%s.%s', getcwd(), CONFORMANCE_FAPI_DIRECTORY, $clientId, $extension);
    $contents = is_file($path) ? file_get_contents($path) : false;
    if ($contents === false) {
        io()->error(sprintf('%s holds nothing for the client "%s": run "castor provision" first.', CONFORMANCE_FAPI_DIRECTORY, $clientId));
        exit(1);
    }

    return $read($contents);
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
/**
 * Takes back what the development user granted the clients of a run, for the modules that need to see
 * them ask again (CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT).
 *
 * @param list<string> $clients
 */
function conformance_forget_consents(string $module, array $clients): void
{
    if (! in_array($module, CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT, true)) {
        return;
    }
    foreach ($clients as $clientId) {
        op_console(['heidi:user:revoke-consent', DEV_USERNAME, $clientId], context()->withQuiet());
    }
}

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
    $created = conformance_request(
        $suite,
        'POST',
        '/api/runner',
        [
            'query' => $query,
            // The configuration is the plan's, or the module's own when it has no plan; an empty POST must not
            // be declared as a form.
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            ...(
                $planId === null
                    ? [
                        'body' => $configuration,
                    ] : []
            ),
        ],
        201,
    );
    $id = (string) $created['id'];
    $url = sprintf('%s/log-detail.html?log=%s', $suite, $id);
    $deadline = microtime(true) + CONFORMANCE_MODULE_TIMEOUT;

    $state = conformance_wait_state($suite, $id, ['CONFIGURED', 'WAITING', 'FINISHED'], $deadline);
    if ($state === 'CONFIGURED') {
        if ($beforeStart === 'rotate') {
            conformance_rotate_signing_key();
        }
        $state = conformance_start_module($suite, $id, $deadline);
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
 * Starts a module and returns the state it reached.
 *
 * The suite answers this call with the module as it renders it, and sometimes fails to render it: the
 * scripted browser of the previous module is still landing when the next one is asked for, and the state
 * the answer is built from is not finished being written ("Could not write JSON: null", a 500 while the
 * module starts all the same and runs seconds later). The start is therefore judged on the state of the
 * module and never on what that call answered. A module still CONFIGURED once the confirmation window
 * has passed is one that really did not start, and it is asked once more.
 */
function conformance_start_module(string $suite, string $id, float $deadline): string
{
    $start = static fn (): array => conformance_request(
        $suite,
        'POST',
        sprintf('/api/runner/%s', $id),
        [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
        ],
        null,
    );

    $start();
    if (
        conformance_wait_state($suite, $id, ['RUNNING', 'WAITING', 'FINISHED'], min($deadline, microtime(true) + CONFORMANCE_START_CONFIRMATION)) === 'TIMEOUT'
    ) {
        io()->text('  the suite did not report the module started; asking it again');
        $start();
    }

    return conformance_wait_state($suite, $id, ['WAITING', 'FINISHED'], $deadline);
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
 * $expected is the status the call must answer, or null when the answer is not what the call is judged
 * on.
 *
 * @param array<string, mixed> $options
 * @return array<mixed>
 */
function conformance_request(string $suite, string $method, string $path, array $options = [], ?int $expected = 200): array
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
    if ($expected !== null && $status !== $expected) {
        throw new RuntimeException(sprintf('%s %s answered %d: %s', $method, $path, $status, mb_substr($content, 0, 500)));
    }
    if ($content === '') {
        return [];
    }
    $decoded = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);

    return (
        is_array($decoded)
            ? $decoded
            : [
                'value' => $decoded,
            ]
    );
}
