<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Console\Input\InputOption;

/**
 * One client per logout channel: a module of the suite fails on a logout request it did not expect.
 */
const CONFORMANCE_FRONT_CHANNEL_CLIENT = [
    'client_id' => 'conformance-front-channel-logout',
    'client_secret' => '{CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET}',
];

const CONFORMANCE_BACK_CHANNEL_CLIENT = [
    'client_id' => 'conformance-back-channel-logout',
    'client_secret' => '{CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET}',
];

const CONFORMANCE_FAPI_PRIVATE_KEY_JWT_CLIENTS = ['conformance-fapi-private-key-jwt', 'conformance-fapi-private-key-jwt-second'];

const CONFORMANCE_FAPI_MTLS_CLIENTS = ['conformance-fapi-mtls', 'conformance-fapi-mtls-second'];

const CONFORMANCE_FAPI_SIGNING_PRIVATE_KEY_JWT_CLIENTS = ['conformance-fapi-signing-private-key-jwt', 'conformance-fapi-signing-private-key-jwt-second'];

const CONFORMANCE_FAPI_SIGNING_MTLS_CLIENTS = ['conformance-fapi-signing-mtls', 'conformance-fapi-signing-mtls-second'];

const CONFORMANCE_CIBA_POLL_CLIENTS = ['conformance-ciba-poll', 'conformance-ciba-poll-second'];

const CONFORMANCE_CIBA_PING_CLIENTS = ['conformance-ciba-ping', 'conformance-ciba-ping-second'];

const CONFORMANCE_CIBA_HINT_TYPE = 'login_hint';

const CONFORMANCE_CIBA_HINT_VALUE = '{BEFFROI_DEV_USER_SUBJECT}';

/**
 * The single-factor class of the default policy, the only one the password-only development user reaches.
 */
const CONFORMANCE_CIBA_ACR_VALUE = '1';

const CONFORMANCE_CIBA_APPROVAL_PATH = '/ciba/conformance/approval';

const CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT = ['fapi2-security-profile-final-user-rejects-authentication'];

const CONFORMANCE_FAPI_DIRECTORY = 'var/conformance';

/**
 * More than one scope: a module of the suite changes their order.
 */
const CONFORMANCE_FAPI_SCOPE = 'openid profile email offline_access';

/**
 * The algorithm of the keys "castor provision" generates into var/conformance/.
 */
const CONFORMANCE_FAPI_DPOP_ALGORITHM = 'ES256';

const CONFORMANCE_FAPI_RESOURCE_PATH = '/userinfo';

const CONFORMANCE_FAPI_KNOWN_MODULES = [
    'fapi2-security-profile-final-test-claims-parameter-identity-claims' => [
        'result' => 'WARNING',
        'findings' => ['WARNING CheckForUnexpectedClaimsInIdToken:'],
        'reason' => 'the ID token carries "sid", a claim Front-Channel Logout 1.0 §3 defines and the suite does not know; beffroi#210',
    ],
];

const CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE = 'the plan signs the URL of the token endpoint as the "aud" of its client assertions, which draft-ietf-oauth-rfc7523bis section 4 forbids and decision 0016 refuses; beffroi#379';

const CONFORMANCE_TOKEN_ENDPOINT_STATUS = 'FAILURE CheckTokenEndpointHttpStatus200:';

const CONFORMANCE_DYNAMIC_SIGNED_REQUEST_OBJECT_CLAIMS = 'the plan signs a request object carrying neither exp nor nbf, which decision 0012 asks of every signed object and which two modules of the FAPI 2 security runs require to be refused; beffroi#385';

const CONFORMANCE_DYNAMIC_UNSIGNED_REQUEST_OBJECT = 'the plan sends an unsigned request object from a client that registered no request_object_signing_alg, which decision 0012 reads from the client that registered "none" and from no other; beffroi#385';

/**
 * The wording is matched too: the failing condition is the runner itself, and a module failing otherwise
 * must fail the run.
 */
const CONFORMANCE_BROWSER_TIMEOUT = 'FAILURE WebRunner: Timed out waiting:';

const CONFORMANCE_DYNAMIC_KNOWN_MODULES = [
    'oidcc-discovery-endpoint-verification' => [
        'result' => 'FAILED',
        'findings' => [
            'FAILURE OIDCCCheckDiscEndpointResponseTypesSupportedDynamic:',
            'FAILURE OIDCCCheckDiscEndpointGrantTypesSupportedDynamic:',
        ],
        'reason' => 'the Dynamic OP profile requires the implicit grant and the hybrid response types, which decision 0006 refuses; beffroi#371',
    ],
    'oidcc-server' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-server:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-idtoken-rs256' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-idtoken-rs256:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-userinfo-rs256' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-userinfo-rs256:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-redirect-uri-query-OK' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-redirect-uri-query-OK:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-registration-jwks-uri' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-registration-jwks-uri:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-refresh-token' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-refresh-token:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-refresh-token-rp-key-rotation' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_TOKEN_ENDPOINT_STATUS,
            'INTERRUPTED oidcc-refresh-token-rp-key-rotation:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_ASSERTION_AUDIENCE,
    ],
    'oidcc-request-uri-signed-rs256' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_BROWSER_TIMEOUT,
            'FAILURE oidcc-request-uri-signed-rs256: Web Runner Exception: Timed out waiting:',
            'INTERRUPTED oidcc-request-uri-signed-rs256:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_SIGNED_REQUEST_OBJECT_CLAIMS,
    ],
    'oidcc-request-uri-unsigned' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_BROWSER_TIMEOUT,
            'FAILURE oidcc-request-uri-unsigned: Web Runner Exception: Timed out waiting:',
            'INTERRUPTED oidcc-request-uri-unsigned:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_UNSIGNED_REQUEST_OBJECT,
    ],
    'oidcc-ensure-request-object-with-redirect-uri' => [
        'result' => 'FAILED',
        'findings' => [
            CONFORMANCE_BROWSER_TIMEOUT,
            'FAILURE oidcc-ensure-request-object-with-redirect-uri: Web Runner Exception: Timed out waiting:',
            'INTERRUPTED oidcc-ensure-request-object-with-redirect-uri:',
        ],
        'reason' => CONFORMANCE_DYNAMIC_UNSIGNED_REQUEST_OBJECT,
    ],
];

const CONFORMANCE_ROTATE_KEYS_BEFORE_START = [
    'oidcc-server-rotate-keys' => 'rotate',
];

const CONFORMANCE_DYNAMIC_CLIENT_NAME = 'OpenID conformance suite';

const CONFORMANCE_DYNAMIC_SECOND_CLIENT_NAME = 'OpenID conformance suite, second client';

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
    'front-channel-logout' => [
        'name' => 'oidcc-frontchannel-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
        'client' => CONFORMANCE_FRONT_CHANNEL_CLIENT,
    ],
    'back-channel-logout' => [
        'name' => 'oidcc-backchannel-rp-initiated-logout-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
            'client_registration' => 'static_client',
        ],
        'client' => CONFORMANCE_BACK_CHANNEL_CLIENT,
    ],
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
    'fapi-ciba-poll' => [
        'name' => 'fapi-ciba-id1-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'ciba_mode' => 'poll',
            'fapi_ciba_profile' => 'plain_fapi',
            'client_registration' => 'static_client',
        ],
        'ciba' => [
            'clients' => CONFORMANCE_CIBA_POLL_CLIENTS,
        ],
    ],
    'fapi-ciba-ping' => [
        'name' => 'fapi-ciba-id1-test-plan',
        'variant' => [
            'client_auth_type' => 'private_key_jwt',
            'ciba_mode' => 'ping',
            'fapi_ciba_profile' => 'plain_fapi',
            'client_registration' => 'static_client',
        ],
        'ciba' => [
            'clients' => CONFORMANCE_CIBA_PING_CLIENTS,
        ],
    ],
    'dynamic' => [
        'name' => 'oidcc-dynamic-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
        ],
        'registers_its_own_clients' => true,
        'before_start' => CONFORMANCE_ROTATE_KEYS_BEFORE_START,
        'known' => CONFORMANCE_DYNAMIC_KNOWN_MODULES,
    ],
    'third-party-init' => [
        'name' => 'oidcc-3rdparty-init-login-certification-test-plan',
        'variant' => [
            'response_type' => 'code',
        ],
        'registers_its_own_clients' => true,
    ],
    'rotate-keys' => [
        'name' => 'oidcc-server-rotate-keys',
        'module' => true,
        'variant' => [
            'server_metadata' => 'discovery',
        ],
        'before_start' => CONFORMANCE_ROTATE_KEYS_BEFORE_START,
    ],
];

/**
 * REVIEW and SKIPPED are results no run of a plan can avoid.
 */
const CONFORMANCE_UNCONDITIONALLY_ACCEPTED = ['PASSED', 'REVIEW', 'SKIPPED'];

const CONFORMANCE_CONFIGURATION = 'tests/conformance/configuration.json';

/**
 * The page of the OP each module that asks for a capture wants; the browser of compose.yaml reads it too.
 */
const CONFORMANCE_CAPTURE_PAGES = 'tests/conformance/browser/captures.json';

/**
 * Relative to the root of the repository; compose.yaml mounts it in the browser at /captures.
 */
const CONFORMANCE_CAPTURES = 'var/conformance/captures';

const CONFORMANCE_BROWSER = 'conformance-browser';

const CONFORMANCE_REQUIRED_VALUES = [
    'BEFFROI_ISSUER',
    'BEFFROI_MTLS_ORIGIN',
    'BEFFROI_DEV_USER_PASSWORD',
    'CONFORMANCE_BASIC_SECRET',
    'CONFORMANCE_BASIC_SECOND_SECRET',
    'CONFORMANCE_POST_SECRET',
    'CONFORMANCE_FRONT_CHANNEL_LOGOUT_SECRET',
    'CONFORMANCE_BACK_CHANNEL_LOGOUT_SECRET',
    'BEFFROI_DEV_USER_SUBJECT',
];

const CONFORMANCE_MODULE_TIMEOUT = 300;

/**
 * Seconds a module is given to leave CONFIGURED before its start is asked for again.
 */
const CONFORMANCE_START_CONFIRMATION = 15;

const CONFORMANCE_SUITE_TIMEOUT = 180;

const CONFORMANCE_OP_TIMEOUT = 180;

/**
 * @param array<string> $plan
 * @param array<string> $module
 */
#[AsTask(
    description: 'Run the certification plans the OP answers (Basic OP, Config OP, Form Post OP, the three logout profiles, the four runs of FAPI 2, the two runs of FAPI-CIBA, the Dynamic OP and 3rd Party-Init OP plans whose clients register themselves, and the key rotation module run on its own) against it through the API of the suite started by "castor start --conformance", the scripted browser of the suite signing in as the development user, the browser of compose.yaml capturing the page of the OP a module asks a screenshot of into var/conformance/captures/, and the task rotating the signing key when the suite asks for it, and print the result of every module',
)]
function conformance(
    #[AsOption(
        description: 'Run only this plan: basic, config, form-post, rp-initiated-logout, front-channel-logout, back-channel-logout, fapi2-security-dpop, fapi2-security-mtls, fapi2-signing-dpop, fapi2-signing-mtls, fapi-ciba-poll, fapi-ciba-ping, dynamic, third-party-init or rotate-keys (repeatable); every plan by default',
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
        $env = conformance_reset($env['BEFFROI_ISSUER']);
    }
    if (array_any($plans, static fn (array $definition): bool => (bool) ($definition['registers_its_own_clients'] ?? false))) {
        conformance_open_registration($env['BEFFROI_ISSUER']);
    }

    $captured = conformance_captured_modules();

    $server = conformance_server($suite);
    io()->text(sprintf('Suite %s (%s) on %s, OP %s', $server['version'] ?? '?', $server['tag'] ?? '?', $suite, $env['BEFFROI_ISSUER']));
    $rows = [];
    $verdict = [];
    $stale = [];
    $planUrls = [];
    $accepted = $strict ? [...CONFORMANCE_UNCONDITIONALLY_ACCEPTED, 'KNOWN'] : [...CONFORMANCE_UNCONDITIONALLY_ACCEPTED, 'KNOWN', 'WARNING'];
    $unpassed = [];
    $failed = 0;
    foreach ($plans as $short => $definition) {
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
            $configuration = conformance_configuration($env, $definition, $captured);
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
            conformance_forget_consents($name, conformance_clients_of($definition));
            $started = microtime(true);
            $run = conformance_run_module(
                $suite,
                $planId,
                $moduleDefinition,
                $configuration,
                ($definition['before_start'] ?? [])[$name] ?? null,
                in_array($name, $captured, true) ? static fn (string $id): array => conformance_capture($suite, $short, $name, $id, $env) : null,
            );
            if ($planUrl === null) {
                $planUrls[] = sprintf('%s: %s', $name, $run['url']);
            }
            $elapsed = microtime(true) - $started;
            $known = $definition['known'][$name] ?? null;
            $result = $run['result'];
            $beyond = $known === null ? [] : conformance_beyond_known($known, $run);
            if ($known !== null && $beyond === []) {
                $result = 'KNOWN';
            }
            $rows[] = [$definition['name'], $name, $result, sprintf('%ds', (int) $elapsed), $run['url']];
            $verdict[$result] = ($verdict[$result] ?? 0) + 1;
            if (! in_array($result, $accepted, true)) {
                if (($definition['waiting_on'] ?? []) === []) {
                    ++$failed;
                } else {
                    $unpassed[$short][] = sprintf('%s: %s', $name, $result);
                }
            }
            io()->text(sprintf(
                '  %s in %ds: %s',
                $result === 'KNOWN' ? sprintf('%s, known (%s)', $run['result'], $known['reason']) : $result,
                (int) $elapsed,
                $run['url'],
            ));
            foreach ($run['findings'] as $finding) {
                io()->text('    ' . $finding);
            }
            if ($beyond !== []) {
                io()->warning([
                    sprintf('%s is listed as known (%s), and this run is not that gap:', $name, $known['reason']),
                    ...$beyond,
                ]);
            }
            if ($known !== null && in_array($result, CONFORMANCE_UNCONDITIONALLY_ACCEPTED, true)) {
                $stale[] = sprintf('%s: %s (listed as known: %s)', $definition['name'], $name, $known['reason']);
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

    if ($stale !== []) {
        io()->error(['These modules no longer fail and must leave the "known" list of CONFORMANCE_PLANS:', ...$stale]);
        exit(1);
    }

    $passing = [];
    foreach ($plans as $short => $definition) {
        $waitingOn = $definition['waiting_on'] ?? [];
        if ($waitingOn === []) {
            continue;
        }
        if (($unpassed[$short] ?? []) !== []) {
            io()->warning([
                sprintf(
                    '%s does not pass yet and waits on %s; %d module(s) of it:',
                    $short,
                    implode(', ', $waitingOn),
                    count($unpassed[$short]),
                ),
                ...$unpassed[$short],
            ]);

            continue;
        }
        if ($module === []) {
            $passing[] = sprintf('%s (waiting on %s)', $short, implode(', ', $waitingOn));
        }
    }
    if ($passing !== []) {
        io()->error(['These runs pass whole and must lose their "waiting_on" line in CONFORMANCE_PLANS:', ...$passing]);
        exit(1);
    }

    if ($failed > 0) {
        io()->error(sprintf('%d module(s) did not pass.', $failed));
        exit(1);
    }
    $known = $verdict['KNOWN'] ?? 0;
    io()->success(
        $known === 0
            ? 'Every module of the runs that gate passed.'
            : sprintf('Every module of the runs that gate passed but %d left to a gap named in CONFORMANCE_PLANS.', $known),
    );
}

/**
 * @param array{result: string, findings: list<string>, reason: string} $known
 * @param array{result: string, url: string, findings: array<string>} $run
 * @return list<string>
 */
function conformance_beyond_known(array $known, array $run): array
{
    $beyond = $run['result'] === $known['result']
        ? []
        : [sprintf('it ended in %s, where %s is what is written down', $run['result'], $known['result'])];
    foreach ($run['findings'] as $finding) {
        if (! array_any($known['findings'], static fn (string $expected): bool => str_starts_with($finding, $expected))) {
            $beyond[] = $finding;
        }
    }

    return $beyond;
}

function conformance_open_registration(string $issuer): void
{
    // The development OP is served by the internal CA of Caddy, which nothing on the host trusts.
    $url = $issuer . '/.well-known/openid-configuration';
    try {
        $document = json_decode(http_request('GET', $url, [
            'verify_peer' => false,
            'verify_host' => false,
        ])->getContent(), true, flags: \JSON_THROW_ON_ERROR);
    } catch (Throwable $exception) {
        io()->error(sprintf('%s could not be read: %s', $url, $exception->getMessage()));
        exit(1);
    }
    if (! is_array($document) || ! is_string($document['registration_endpoint'] ?? null)) {
        io()->error([
            sprintf('%s announces no "registration_endpoint", so no client can register itself.', $url),
            sprintf(
                'The runs that register their own clients need the tenant to register whoever asks, BEFFROI_REGISTRATION_MODE="open", which "castor provision" writes into %s (decision 0009).',
                DEV_ENV_LOCAL,
            ),
        ]);
        exit(1);
    }
    io()->text(sprintf('Clients register themselves on %s.', $document['registration_endpoint']));
}

/**
 * The suite, once it answers: its container reports healthy before its JVM serves the API.
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
 * Restarts the containers last: a FrankenPHP worker keeps the signing key it opened until its source
 * changes, and no row names that key after the reset. The environment is read again after the
 * provisioning, which issues the development user a new subject.
 *
 * @return array<string, string> the environment of the application
 */
function conformance_reset(string $issuer): array
{
    io()->section('Resetting the OP');
    op_console(['doctrine:schema:drop', '--full-database', '--force', '--no-interaction']);
    op_console(['doctrine:migrations:migrate', '--no-interaction', '--all-or-nothing']);
    provision();
    run(['docker', 'compose', ...compose_profiles(), 'restart', 'op', 'worker']);
    // Last, after the containers they follow, or the back-channel and sector modules wait for what cannot arrive.
    compose_recreate_redirectors(['op', 'worker']);
    conformance_wait_for_op($issuer);

    return load_dot_env(getcwd() . '/apps/op/.env');
}

/**
 * "docker compose restart" returns before the container is healthy.
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
 * @param array<string, string> $env
 * @param array<string, mixed> $definition an entry of CONFORMANCE_PLANS
 * @param list<string> $captured the modules the browser of compose.yaml captures a page for
 */
function conformance_configuration(array $env, array $definition, array $captured): string
{
    $template = file_get_contents(getcwd() . '/' . CONFORMANCE_CONFIGURATION);
    if ($template === false) {
        throw new RuntimeException(sprintf('Cannot read %s.', CONFORMANCE_CONFIGURATION));
    }
    $decoded = json_decode($template, true, 32, \JSON_THROW_ON_ERROR);
    $client = $definition['client'] ?? [];
    $fapi = $definition['fapi'] ?? [];
    $ciba = $definition['ciba'] ?? [];
    if ($client !== []) {
        $decoded['client'] = $client;
    }
    if ($fapi !== []) {
        $decoded = conformance_fapi_sections($decoded, $fapi['clients'], (string) $definition['variant']['sender_constrain']);
    }
    if ($ciba !== []) {
        $decoded = conformance_ciba_sections($decoded, $ciba['clients'], $env);
    }
    if ($definition['registers_its_own_clients'] ?? false) {
        $decoded = conformance_dynamic_sections($decoded);
    }
    // No step of the scripted browser of the suite: it publishes the URLs of the module, which conformance_capture() visits.
    foreach ($captured as $module) {
        $decoded['override'][$module] = [
            'browser' => [],
        ];
    }
    $template = json_encode($decoded, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT);
    $values = [
        '{BEFFROI_DEV_USERNAME}' => DEV_USERNAME,
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
 * @param array<string, mixed> $configuration
 * @return array<string, mixed>
 */
function conformance_dynamic_sections(array $configuration): array
{
    unset($configuration['client_secret_post']);
    $configuration['client'] = [
        'client_name' => CONFORMANCE_DYNAMIC_CLIENT_NAME,
    ];
    $configuration['client2'] = [
        'client_name' => CONFORMANCE_DYNAMIC_SECOND_CLIENT_NAME,
    ];

    return $configuration;
}

/**
 * @param array<string, mixed> $configuration
 * @param list<string> $clients "client" then "client2"
 * @param string $senderConstrain "dpop" or "mtls"
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
    $configuration['resource'] = [
        'resourceUrl' => ($certificates ? '{BEFFROI_MTLS_ORIGIN}' : '{BEFFROI_ISSUER}') . CONFORMANCE_FAPI_RESOURCE_PATH,
    ];

    return $configuration;
}

/**
 * Certificates though the clients authenticate with private_key_jwt: the suite configures no static client
 * of this plan without one.
 *
 * @param array<string, mixed> $configuration
 * @param list<string> $clients "client" then "client2"
 * @param array<string, string> $env
 * @return array<string, mixed>
 */
function conformance_ciba_sections(array $configuration, array $clients, array $env): array
{
    $configuration = conformance_fapi_sections($configuration, $clients, 'mtls');
    foreach (['client', 'client2'] as $section) {
        $configuration[$section]['hint_type'] = CONFORMANCE_CIBA_HINT_TYPE;
        $configuration[$section]['hint_value'] = CONFORMANCE_CIBA_HINT_VALUE;
        $configuration[$section]['acr_value'] = CONFORMANCE_CIBA_ACR_VALUE;
    }
    // Not left as placeholders: a password in a query must be encoded, which the filling of the file does not do.
    $configuration['automated_ciba_approval_url'] = sprintf(
        '%s%s?%s',
        $env['BEFFROI_ISSUER'],
        CONFORMANCE_CIBA_APPROVAL_PATH,
        implode('&', [
            http_build_query([
                'username' => DEV_USERNAME,
                'password' => $env['BEFFROI_DEV_USER_PASSWORD'],
            ]),
            // The suite substitutes these itself.
            'auth_req_id={auth_req_id}',
            'action={action}',
        ]),
    );

    return $configuration;
}

/**
 * The key goes whole, private half included: the suite is the client.
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
 * @template T
 * @param callable(string): T $read
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
 * @param array<string, mixed> $definition an entry of CONFORMANCE_PLANS
 * @return list<string>
 */
function conformance_clients_of(array $definition): array
{
    return $definition['fapi']['clients'] ?? $definition['ciba']['clients'] ?? [];
}

/**
 * @param list<string> $clients
 */
function conformance_forget_consents(string $module, array $clients): void
{
    if (! in_array($module, CONFORMANCE_MODULES_NEEDING_A_FRESH_CONSENT, true)) {
        return;
    }
    foreach ($clients as $clientId) {
        op_console(['beffroi:user:revoke-consent', DEV_USERNAME, $clientId], context()->withQuiet());
    }
}

/**
 * @param array{testModule: string, variant?: array<string, string>} $definition
 * @param null|Closure(string): list<string> $browser drives the module once it waits for a browser, and says why it failed
 * @return array{result: string, url: string, findings: array<string>}
 */
function conformance_run_module(
    string $suite,
    ?string $planId,
    array $definition,
    string $configuration = '',
    ?string $beforeStart = null,
    ?Closure $browser = null,
): array {
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
            // JSON even when empty: an empty POST must not be declared as a form.
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
    $failure = [];
    if ($browser !== null && $state === 'WAITING') {
        $failure = $browser($id);
        if ($failure !== []) {
            // At once, rather than the five minutes the module would wait for the page it asked for.
            conformance_request($suite, 'DELETE', sprintf('/api/runner/%s', $id), [], null);
        }
        $state = conformance_wait_state($suite, $id, ['FINISHED'], $deadline);
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
    $result = $failure === [] ? (string) ($info['result'] ?? ($state === 'FINISHED' ? 'UNKNOWN' : $state)) : 'FAILED';
    $findings = array_map(static fn (string $line): string => 'CAPTURE ' . $line, $failure);
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
 * @return list<string>
 */
function conformance_captured_modules(): array
{
    $pages = json_decode((string) file_get_contents(getcwd() . '/' . CONFORMANCE_CAPTURE_PAGES), true, 2, \JSON_THROW_ON_ERROR);
    if (! is_array($pages)) {
        throw new RuntimeException(sprintf('%s is not an object of modules.', CONFORMANCE_CAPTURE_PAGES));
    }

    return array_map(strval(...), array_keys($pages));
}

/**
 * The browser of compose.yaml runs the module to the page it asks for, captures it under CONFORMANCE_CAPTURES
 * and sends it to the module (tests/conformance/browser/capture.mjs).
 *
 * @param array<string, string> $env the environment of the application
 * @return list<string> what the browser did, when it failed; nothing when the page was captured
 */
function conformance_capture(string $suite, string $plan, string $module, string $id, array $env): array
{
    static $running = false;
    if (! $running && ! in_array(CONFORMANCE_BROWSER, compose_running_services(), true)) {
        io()->error(sprintf('The service %s of compose.yaml is not running: "castor start --conformance" starts it with the suite.', CONFORMANCE_BROWSER));
        exit(1);
    }
    $running = true;
    $environment = [
        'BEFFROI_ISSUER' => $env['BEFFROI_ISSUER'],
        'BEFFROI_DEV_USERNAME' => DEV_USERNAME,
        'BEFFROI_DEV_USER_PASSWORD' => $env['BEFFROI_DEV_USER_PASSWORD'],
        'CONFORMANCE_SUITE' => $suite,
    ];
    if (! conformance_suite_is_local($suite)) {
        $environment['CONFORMANCE_SUITE_API'] = $suite;
    }
    $token = getenv('CONFORMANCE_TOKEN');
    if (is_string($token) && $token !== '') {
        $environment['CONFORMANCE_TOKEN'] = $token;
    }
    $passed = [];
    foreach (array_keys($environment) as $name) {
        // By name: the value stays in the environment of the process, out of its command line.
        $passed[] = '-e';
        $passed[] = $name;
    }
    $driver = run(
        [
            'docker',
            'compose',
            ...compose_profiles(),
            'exec',
            '-T',
            '--user',
            sprintf('%s:%s', getmyuid(), getmygid()),
            ...$passed,
            CONFORMANCE_BROWSER,
            'node',
            '/browser/driver/capture.mjs',
            $plan,
            $module,
            $id,
        ],
        context: context()->withEnvironment($environment)->withAllowFailure()->withQuiet()->withTimeout(CONFORMANCE_MODULE_TIMEOUT),
    );
    $lines = preg_split('/\R/', trim($driver->getOutput() . "\n" . $driver->getErrorOutput())) ?: [];
    if (! $driver->isSuccessful()) {
        return array_values(array_filter($lines, static fn (string $line): bool => $line !== ''));
    }
    foreach ($lines as $line) {
        if (str_starts_with($line, 'captured ')) {
            io()->text(sprintf('  captured %s/%s', CONFORMANCE_CAPTURES, substr($line, strlen('captured '))));
        }
    }

    return [];
}

/**
 * Judged on the state of the module: the suite may answer 500 to a start that succeeds.
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
 * With --now the new key signs at once and the old one stays in the JWK Set, which is what the module checks.
 */
function conformance_rotate_signing_key(): void
{
    io()->text('  The suite asks for a rotation: "beffroi:keys:rotate --now" on the OP.');
    $rotated = op_console(['beffroi:keys:rotate', '--now', '--no-ansi'], context()->withAllowFailure()->withQuiet());
    if (! $rotated->isSuccessful()) {
        io()->error(['The signing key could not be rotated; the module will see no new key.', trim($rotated->getErrorOutput() . $rotated->getOutput())]);

        return;
    }
    foreach (preg_split('/\R/', trim($rotated->getOutput())) ?: [] as $line) {
        io()->text('  ' . $line);
    }
}

/**
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
 * The suite of "castor start --conformance" serves a self-signed certificate for localhost.
 *
 * @param array<string, mixed> $options
 * @return array<mixed>
 */
function conformance_request(string $suite, string $method, string $path, array $options = [], ?int $expected = 200): array
{
    $local = conformance_suite_is_local($suite);
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

function conformance_suite_is_local(string $suite): bool
{
    return in_array(parse_url($suite, \PHP_URL_HOST), ['localhost', '127.0.0.1', '::1'], true);
}
