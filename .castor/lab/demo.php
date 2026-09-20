<?php

declare(strict_types=1);

/*
 * oidc-demo (Symfony oidc_login) against the stack: the experiments of the spikes, one request at a time from
 * the command line, so that every step is looked at (--check, --rotate, --passkey).
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use Castor\Context;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;

/**
 * oidc-demo, the reference client of the core (Symfony's oidc_login): where it is checked out, next to this
 * repository or next to the repository this one is nested in, where its server listens, and the client the
 * application registers for it (apps/op/config/packages/heidi.yaml).
 */
const DEMO_DIRS = ['../oidc-demo', '../../oidc-demo'];

const DEMO_URL = 'https://localhost:8002';

const DEMO_CLIENT_ID = 'oidc-demo';

#[AsTask(description: 'Point oidc-demo (Symfony oidc_login) at the development OP and start it on https://localhost:8002: its .env.local takes the issuer, the client and the secret of apps/op/.env.local, its php.ini trusts the CA of Caddy; --check then signs in as "alice", opens /profile and logs out from the command line; --rotate runs a whole key rotation against it, with short windows for the run, and measures what oidc_login does on an unknown "kid"; --passkey signs in with a password, is sent back for a passkey by /vault (acr_values=phr) and signs the assertion with a software authenticator')]
function demo(
    #[AsOption(description: 'Where oidc-demo is checked out; ../oidc-demo or ../../oidc-demo by default')]
    ?string $dir = null,
    #[AsOption(description: 'Sign in as the development user, open /profile and log out, from the command line, and print what was verified')]
    bool $check = false,
    #[AsOption(description: 'The second success criterion of spike 2 (issue #59): sign in, rotate the signing key of the OP, let the scheduled step activate it, sign in again, refresh, log out, retire the old key, then measure the refetch cooldown of oidc_login; the JWK Set max-age and the token lifetimes are shortened in apps/op/.env.local for the time of the run (about six minutes)')]
    bool $rotate = false,
    #[AsOption(description: 'The third success criterion of spike 3 (issue #93): sign in with a password, open /profile, be sent back to the OP by /vault with acr_values=phr and prompt=login, enrol a passkey and sign the assertion with a software authenticator (tests/demo/passkey-browser.php), open /vault with an ID token carrying acr=phr, log out; the passkey is revoked afterwards')]
    bool $passkey = false,
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
    if ($rotate) {
        demo_rotation_check($server, $env['HEIDI_ISSUER'], $env['HEIDI_DEV_USER_PASSWORD'], $ca);
    }
    if ($passkey) {
        demo_passkey_check($env['HEIDI_ISSUER'], $env['HEIDI_DEV_USER_PASSWORD'], $ca);
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

    $session = demo_sign_in($cookies, $issuer, $password, $ca);
    $verified[] = ['Authorization request', 'response_type=code, client_id=' . DEMO_CLIENT_ID . ', PKCE S256, nonce, state'];
    $verified[] = ['Authorization response', 'code, state, iss=' . $issuer];
    $idToken = $session['tokens']['id_token']['claims'];
    $accessToken = $session['tokens']['access_token']['claims'];
    $verified[] = ['/profile', sprintf('sub %s, %d claims from UserInfo', $idToken['sub'] ?? '?', preg_match_all('/<tr><th>[a-z_]+<\/th>/', $session['page']))];
    $verified[] = ['ID token', sprintf('nonce, auth_time, acr=%s, amr=%s, at_hash, sid', $idToken['acr'] ?? '?', json_encode($idToken['amr'] ?? null))];
    $verified[] = ['Access token', sprintf('typ=at+jwt, scope="%s", jti %s', $accessToken['scope'] ?? '?', $accessToken['jti'] ?? '?')];

    // RP-Initiated Logout: the demo ends its session and the one of the OP, which sends the browser back
    demo_logout($cookies, $issuer, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), '/profile asks for a new login');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?'), 'the OP asks for a login again: its session ended');
    $verified[] = ['RP-Initiated Logout', 'id_token_hint verified, back to ' . DEMO_URL . '/, the OP asks for a login again'];

    io()
        ->table(['Step', 'Verified'], $verified);
    io()
        ->note(sprintf('The refresh of the access token (refresh_access_token) happens on the first request after it expired, ten minutes after the login (access_token_ttl of the application): sign in from a browser, open %s/profile again then and compare the "jti"; "castor demo --rotate" sees it happen with a shorter lifetime.', DEMO_URL));
    io()
        ->success('oidc-demo signed in, opened /profile and logged out against the OP, without a patch.');
}

/**
 * The browser with a software authenticator of the passkey check: the enrolment and the assertion, driven
 * over HTTP against the OP by the SoftwareAuthenticator of the functional tests, under the autoloader of
 * the monorepo, which castor does not load.
 */
const DEMO_PASSKEY_BROWSER = 'tests/demo/passkey-browser.php';

/**
 * The class /vault of the demo requires (OpenID Connect EAP ACR Values 1.0), the one of the default policy
 * of the tenant a passkey proves (decision 0010 of the design repository).
 */
const DEMO_PASSKEY_CLASS = 'phr';

/**
 * The third success criterion of spike 3 (issue #93): oidc-demo, on Symfony's oidc_login without a patch,
 * requires a phishing-resistant login on /vault and gets one. From the command line, one request at a
 * time as demo_check: a password sign-in through the demo and /profile open, whose ID token says acr "1";
 * /vault, which access_control protects with IS_AUTHENTICATED_IN_CONTEXT:phr, sends the browser back to
 * the authorization endpoint with acr_values=phr, prompt=login and the previous ID token as id_token_hint
 * (the re-authentication entry point of oidc_login); the OP asks for a login, where the browser of
 * DEMO_PASSKEY_BROWSER enrols a passkey on the account of its session and signs the assertion; the OP
 * records the proof on the same session, resumes the interaction and sends the browser to the callback
 * with a code; the demo verifies the new ID token (acr=phr, "hwk" in amr, the same sid, a later auth_time)
 * and opens /vault, which prints what oidc_login recorded on the security token. Then the RP-Initiated
 * Logout round trip, across the step-up: one session, one sid. The passkey is revoked at the end, so that
 * the user is left as found.
 */
function demo_passkey_check(string $issuer, string $password, string $ca): void
{
    io()
        ->section('Sign in with a password, /vault asks for a passkey, logout');
    $cookies = [];
    $verified = [];
    $host = (string) parse_url($issuer, \PHP_URL_HOST);

    $session = demo_sign_in($cookies, $issuer, $password, $ca);
    $before = $session['tokens']['id_token']['claims'];
    demo_expect(($before['acr'] ?? null) !== DEMO_PASSKEY_CLASS, sprintf('the ID token of a password login says acr=%s, not %s', json_encode($before['acr'] ?? null), DEMO_PASSKEY_CLASS));
    $verified[] = ['Password login', sprintf('/profile open, acr=%s, amr=%s, auth_time %s, sid %s', $before['acr'] ?? '?', json_encode($before['amr'] ?? null), $before['auth_time'] ?? '?', $before['sid'] ?? '?')];

    // /vault: the demo denies IS_AUTHENTICATED_IN_CONTEXT:phr and starts the re-authentication
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/vault');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), sprintf('/vault sends the browser back to the authorization endpoint (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
    demo_expect(($authorization['acr_values'] ?? null) === DEMO_PASSKEY_CLASS && ($authorization['prompt'] ?? null) === 'login', sprintf('the authorization request carries acr_values=%s and prompt=login', DEMO_PASSKEY_CLASS));
    demo_expect(($authorization['id_token_hint'] ?? null) === $session['tokens']['id_token']['raw'], 'the authorization request carries the previous ID token as id_token_hint');
    demo_expect(($authorization['code_challenge_method'] ?? null) === 'S256' && isset($authorization['state'], $authorization['nonce']), 'it stays an ordinary authorization request: PKCE S256, state, nonce');
    $verified[] = ['/vault', sprintf('302 to the OP with acr_values=%s, prompt=login, id_token_hint', DEMO_PASSKEY_CLASS)];

    // the OP holds the session of the password login and asks for a login anyway (prompt=login)
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?interaction='), sprintf('the OP asks for a login on its existing session (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $login);

    // the browser with the software authenticator: a passkey enrolled, the assertion signed and posted
    io()
        ->text(' <comment>tests/demo/passkey-browser.php</comment>');
    $browser = run(['php', DEMO_PASSKEY_BROWSER], context: context()->withQuiet()->withAllowFailure()->withEnvironment([
        'XDEBUG_MODE' => 'off',
    ])->withInput(json_encode([
        'issuer' => $issuer,
        'cafile' => $ca,
        'cookies' => $cookies[$host] ?? [],
        'interaction' => (string) ($login['interaction'] ?? ''),
        'name' => 'castor demo --passkey ' . date('Y-m-d H:i:s'),
    ], \JSON_THROW_ON_ERROR)));
    // the steps of the browser, then the reason of a failure without the trace of the exception that ends it
    foreach (explode("\n", rtrim($browser->getErrorOutput(), "\n")) as $line) {
        if (str_starts_with($line, 'Stack trace:')) {
            break;
        }
        if ($line !== '') {
            io()->text(' ' . preg_replace('/^PHP Fatal error:\s+Uncaught \w+: (.*) in \S+:\d+$/', '$1', $line));
        }
    }
    demo_expect($browser->isSuccessful(), 'the passkey is enrolled and the assertion accepted');
    $passkey = (array) json_decode($browser->getOutput(), true, 4, \JSON_THROW_ON_ERROR);
    $cookies[$host] = (array) ($passkey['cookies'] ?? []);
    $verified[] = ['Passkey', sprintf('enrolled on the account page (credential %s), assertion signed (sign count %d) and accepted on the login page', $passkey['credential_id'] ?? '?', $passkey['sign_count'] ?? 0)];

    // the login page resumes the interaction: the browser goes to the callback with a code
    [$status, $location] = demo_request($cookies, $ca, 'GET', (string) ($passkey['location'] ?? ''));
    demo_expect($status === 302 && str_starts_with($location, DEMO_URL . '/oidc/callback?'), sprintf('the OP sends the browser to the callback of the demo (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $callback);
    demo_expect(isset($callback['code']) && ($callback['state'] ?? null) === $authorization['state'] && ($callback['iss'] ?? null) === $issuer, 'the callback carries a code, the state of the re-authentication and iss');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/vault', sprintf('the demo verifies the ID token and sends the browser back to /vault (got %d %s)', $status, $location));
    $verified[] = ['Callback', 'code exchanged, ID token verified, back to /vault'];

    // /vault opens: what oidc_login recorded from the new ID token
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/vault');
    demo_expect($status === 200, sprintf('/vault opens (got %d)', $status));
    $received = [];
    foreach (['acr', 'amr', 'auth-time', 'sid'] as $name) {
        $received[$name] = preg_match(sprintf('/<code data-%s>([^<]*)<\/code>/', $name), $page, $found) === 1 ? html_entity_decode($found[1]) : '';
    }
    $amr = (array) json_decode($received['amr'], true);
    demo_expect($received['acr'] === DEMO_PASSKEY_CLASS, sprintf('the ID token says acr=%s (got %s)', DEMO_PASSKEY_CLASS, json_encode($received['acr'])));
    demo_expect(in_array('hwk', $amr, true) && in_array('pwd', $amr, true), sprintf('amr lists the passkey and the password of the same session (got %s)', $received['amr']));
    demo_expect($received['sid'] === ($before['sid'] ?? null), sprintf('the sid is the one of the password login: one session on the OP (got %s)', $received['sid']));
    demo_expect((int) $received['auth-time'] >= (int) ($before['auth_time'] ?? 0), sprintf('auth_time is the passkey\'s (%s, was %s)', $received['auth-time'], $before['auth_time'] ?? '?'));
    $verified[] = ['/vault', sprintf('open; oidc_login received acr=%s, amr=%s, auth_time %s, sid %s', $received['acr'], $received['amr'], $received['auth-time'], $received['sid'])];

    // RP-Initiated Logout across the step-up: the hint is the new ID token, the one session ends
    $kid = demo_logout($cookies, $issuer, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), '/profile asks for a new login');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/login?'), 'the OP asks for a login again: its session ended');
    $verified[] = ['RP-Initiated Logout', sprintf('id_token_hint of the step-up verified (kid %s), back to %s/, the OP asks for a login again', $kid, DEMO_URL)];

    // the passkey of the run is revoked: heidi:user:show lists it by its name, heidi:user:revoke-credential takes its identifier
    $shown = op_console(['heidi:user:show', DEV_USERNAME], context()->withQuiet())->getOutput();
    $name = 'castor demo --passkey';
    demo_expect(preg_match('/^\s*passkey\s+([0-9a-f-]{36})\s+' . preg_quote($name, '/') . '/m', $shown, $found) === 1, 'heidi:user:show lists the passkey of the run');
    op_console(['heidi:user:revoke-credential', DEV_USERNAME, $found[1]], context()->withQuiet());
    $verified[] = ['Cleanup', sprintf('passkey %s revoked (heidi:user:revoke-credential)', $found[1])];

    io()
        ->table(['Step', 'Verified'], $verified);
    io()
        ->success(sprintf('oidc-demo required acr_values=%s on /vault and got a passkey login against the OP, without a patch of oidc_login.', DEMO_PASSKEY_CLASS));
}

/**
 * The JWK Set max-age and the JWS lifetimes of the rotation run, seconds: written into apps/op/.env.local
 * for the time of the run (HEIDI_JWKS_MAX_AGE, HEIDI_ACCESS_TOKEN_TTL, HEIDI_ID_TOKEN_TTL, which
 * config/packages/heidi.yaml reads at runtime), so that the staging delay (max-age plus the 60 s cooldown,
 * StagingDelay) and the retirement window (the longest lifetime) fit in minutes rather than in a quarter
 * of an hour. The max-age stays above the cooldown, or the last section could not tell the two apart: a
 * copy that expires before the cooldown elapsed is refreshed, never refetched.
 */
const DEMO_ROTATION_JWKS_MAX_AGE = 90;

const DEMO_ROTATION_TOKEN_TTL = 60;

/**
 * OidcSignatureVerifier::ROTATION_COOLDOWN of Symfony's oidc_login (StagingDelay::ROTATION_COOLDOWN in
 * the bundle): a JWK Set copy younger than this is not refetched on an unknown "kid".
 */
const DEMO_ROTATION_COOLDOWN = 60;

const DEMO_ROTATION_ENV_MARKER = 'castor demo --rotate';

/**
 * The second success criterion of spike 2 (issue #59): oidc-demo, on Symfony's oidc_login without a
 * patch, notices nothing across a rotation. The seven steps of the issue against the running OP and demo,
 * with the windows shortened for the run (DEMO_ROTATION_*): sign in twice; "heidi:keys:rotate", a second
 * key in the JWK Set, staged; the scheduled step of the worker activates it when the staging delay
 * elapsed; a fresh browser session signs in and its ID token names the new key; the first session
 * refreshes its access token, signed by the new key; the second session logs out with the ID token of its
 * login, signed by the key now retiring, without a question; the old key retires at its due date, leaves
 * the JWK Set, and its access token is refused at UserInfo. Then the measurement the issue asks for, on
 * the emergency path ("rotate --now"): what oidc_login does on an unknown "kid" with a cold copy of the
 * JWK Set, a warm one younger than the cooldown, and one older. Every fetch of /jwks by the demo is read
 * in the access log of Caddy (docker compose logs op), by the User-Agent of Symfony's HttpClient.
 */
function demo_rotation_check(Context $server, string $issuer, string $password, string $ca): void
{
    io()
        ->section('A rotation, as scheduled');
    $verified = [];
    $fetches = [];
    $utc = new DateTimeZone('UTC');
    $at = static fn (DateTimeImmutable $date): string => $date->setTimezone($utc)
        ->format('H:i:s');

    $tenant = demo_keys();
    $active = array_keys(array_filter($tenant, static fn (array $key): bool => $key['status'] === 'active'));
    $staged = array_keys(array_filter($tenant, static fn (array $key): bool => $key['status'] === 'staged'));
    demo_expect(count($active) === 1 && $staged === [], sprintf('the tenant has one active key and none staged before the run (got %d active, %d staged: "castor console heidi:keys:list" says which)', count($active), count($staged)));
    $kid1 = $active[0];
    demo_rotation_lifetimes($issuer, $ca, true);
    // A cold JWK Set copy, whatever ran before: the demo caches it in cache.app, with the discovery document.
    run(['php', 'bin/console', 'cache:pool:clear', 'cache.app'], context: $server->withQuiet());
    $before = demo_jwks($issuer, $ca);
    io()
        ->text(sprintf(' <info>✓</info> the run: JWK Set max-age %d s, ID and access tokens %d s, staging delay %d s, retirement window %d s; the key "%s" signs, the JWK Set has %d key(s)', DEMO_ROTATION_JWKS_MAX_AGE, DEMO_ROTATION_TOKEN_TTL, DEMO_ROTATION_JWKS_MAX_AGE + DEMO_ROTATION_COOLDOWN, DEMO_ROTATION_TOKEN_TTL, $kid1, count($before)));

    // 1. Two sessions, both signed by the first key: the first refreshes at step 5, the second logs out at
    // step 6 with the ID token of its login. The demo fetches the JWK Set once, for the first.
    io()
        ->text('<comment>1.</comment> Sign in, twice');
    $start = new DateTimeImmutable();
    $first = [];
    $second = [];
    $sessionA = demo_sign_in($first, $issuer, $password, $ca);
    $sessionB = demo_sign_in($second, $issuer, $password, $ca);
    $signedBy = static fn (array $session, string $token): string => (string) ($session['tokens'][$token]['header']['kid'] ?? '?');
    demo_expect($signedBy($sessionA, 'id_token') === $kid1 && $signedBy($sessionA, 'access_token') === $kid1 && $signedBy($sessionB, 'id_token') === $kid1, sprintf('the ID tokens and the access token name the active key "%s"', $kid1));
    $fetched = demo_jwks_fetches($start);
    demo_expect(count($fetched) === 1, sprintf('the demo fetched the JWK Set once, for the first verification (got %d)', count($fetched)));
    $verified[] = ['1. Sign in, twice', sprintf('ID tokens and access token signed by %s; one fetch of /jwks at %s (cold copy)', $kid1, $at($fetched[0]))];
    $fetches[] = ['Cold copy', $at($fetched[0]), 'The first verification fetches the JWK Set; the second login used the copy'];
    $firstFetch = $fetched[0];

    // 2. The rotation as an operator does it: the new key is published at once and signs later.
    io()
        ->text('<comment>2.</comment> heidi:keys:rotate');
    $kid2 = demo_rotate([]);
    $keys = demo_keys();
    $activationDue = $keys[$kid2]['activates_at'] ?? null;
    demo_expect(($keys[$kid2]['status'] ?? null) === 'staged' && $activationDue !== null, sprintf('the key "%s" is staged with an activation date', $kid2));
    $published = demo_jwks($issuer, $ca);
    demo_expect(count($published) === count($before) + 1 && in_array($kid2, $published, true) && in_array($kid1, $published, true), sprintf('the JWK Set has one key more, the staged one (got %s)', implode(', ', $published)));
    $verified[] = ['2. heidi:keys:rotate', sprintf('%s staged, activates at %s; the JWK Set has %d keys, %s still signs', $kid2, $at($activationDue), count($published), $kid1)];

    // 3. Time activates it: the scheduled step of the worker, every minute (compose.yaml).
    io()
        ->text('<comment>3.</comment> The scheduled step activates the key');
    demo_wait_until($activationDue, sprintf('the staging delay of "%s"', $kid2));
    $deadline = $activationDue->modify('+90 seconds');
    while (($keys = demo_keys())[$kid2]['status'] !== 'active' && new DateTimeImmutable() < $deadline) {
        sleep(3);
    }
    demo_expect($keys[$kid2]['status'] === 'active', sprintf('the scheduled step activated "%s" within 90 s of its date: is the worker running ("docker compose ps worker")? "castor console heidi:keys:activate %s" does it by hand', $kid2, $kid2));
    $activated = new DateTimeImmutable();
    $retirementDue = $keys[$kid1]['retirement_due_at'] ?? null;
    demo_expect($keys[$kid1]['status'] === 'retiring' && $retirementDue !== null, sprintf('the key "%s" is retiring with a retirement date', $kid1));
    io()
        ->text(sprintf(' <info>✓</info> "%s" active at %s, %d s after its date, by the scheduled step; "%s" retiring until %s', $kid2, $at($activated), $activated->getTimestamp() - $activationDue->getTimestamp(), $kid1, $at($retirementDue)));
    $verified[] = ['3. Scheduled activation', sprintf('%s active at %s (%d s after its date), %s retiring until %s', $kid2, $at($activated), $activated->getTimestamp() - $activationDue->getTimestamp(), $kid1, $at($retirementDue))];

    // 4. A fresh browser: the ID token names the new key. The copy of the demo is older than the max-age
    // by now, the login refreshes it as any expired copy, and the new key was in the JWK Set before it signed.
    io()
        ->text('<comment>4.</comment> Sign in again, in a fresh browser session');
    $third = [];
    $since = new DateTimeImmutable();
    $sessionC = demo_sign_in($third, $issuer, $password, $ca);
    demo_expect($signedBy($sessionC, 'id_token') === $kid2 && $signedBy($sessionC, 'access_token') === $kid2, sprintf('the ID token and the access token name the new key "%s"', $kid2));
    $fetched = demo_jwks_fetches($since);
    demo_expect(count($fetched) === 1, sprintf('the demo fetched the JWK Set once during the login (got %d)', count($fetched)));
    $age = $fetched[0]->getTimestamp() - $firstFetch->getTimestamp();
    io()
        ->text(sprintf(' <info>✓</info> one fetch of /jwks at %s, %d s after the copy of step 1, past its max-age of %d s: the refresh of an expired copy, the new key was in it', $at($fetched[0]), $age, DEMO_ROTATION_JWKS_MAX_AGE));
    $verified[] = ['4. Fresh session', sprintf('ID token and access token signed by %s; the demo verified them with a copy refreshed at %s', $kid2, $at($fetched[0]))];
    $fetches[] = ['Expired copy', $at($fetched[0]), sprintf('%d s after the previous fetch, past the max-age: refreshed before any check, the staged key was in it', $age)];

    // 5. The first session: its access token expired (lifetime minus the 30 s leeway of oidc_login), the
    // next request renews it with the refresh token grant; the new tokens are signed by the new key and
    // the demo verifies the new ID token; the refresh token, opaque, is not on the page and not concerned.
    io()
        ->text('<comment>5.</comment> The first session refreshes its access token');
    [$status, , $page] = demo_request($first, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile of the first session opens (got %d)', $status));
    $refreshed = demo_tokens_of($page);
    $jtiBefore = $sessionA['tokens']['access_token']['claims']['jti'] ?? '?';
    $jtiAfter = $refreshed['access_token']['claims']['jti'] ?? '?';
    demo_expect($jtiAfter !== $jtiBefore && ($refreshed['access_token']['header']['kid'] ?? null) === $kid2, sprintf('the access token was renewed (jti %s to %s) and is signed by "%s"', $jtiBefore, $jtiAfter, $kid2));
    demo_expect(($refreshed['id_token']['header']['kid'] ?? null) === $kid2 && ($refreshed['id_token']['claims']['sub'] ?? null) === ($sessionA['tokens']['id_token']['claims']['sub'] ?? '?'), sprintf('the ID token was re-issued, signed by "%s", same sub, and the demo verified it', $kid2));
    $verified[] = ['5. refresh_access_token', sprintf('new at+jwt signed by %s (jti %s to %s), ID token re-issued and verified, same sub', $kid2, $jtiBefore, $jtiAfter)];

    // 6. Logout across the rotation, both ways. Through the demo: /logout runs the refresh listener first
    // (priority 0, the logout listener at -127), so the hint is the ID token just re-issued, signed by the
    // new key. As an oidc_login without refresh_access_token (its default) does it, with the ID token of
    // the login, signed by the key now retiring: the very request OidcEndSessionListener builds,
    // id_token_hint and post_logout_redirect_uri, on the OP session of the first browser.
    io()
        ->text('<comment>6.</comment> Log out, with the re-issued ID token and with the one of the login');
    $hint = demo_logout($second, $issuer, $ca);
    demo_expect($hint === $kid2, sprintf('through the demo, the id_token_hint is the ID token re-issued on the refresh, signed by "%s" (got "%s")', $kid2, $hint));
    [$status, $location] = demo_request($first, $ca, 'GET', $issuer . '/logout?' . http_build_query([
        'id_token_hint' => $sessionA['tokens']['id_token']['raw'],
        'post_logout_redirect_uri' => DEMO_URL . '/',
    ]));
    demo_expect($status === 302 && $location === DEMO_URL . '/', sprintf('with the ID token of the login, signed by "%s" (retiring), the OP ends the session without a question (got %d %s)', $kid1, $status, $location));
    $verified[] = ['6. Logout', sprintf('through the demo, id_token_hint re-issued and signed by %s; with the ID token of the login, signed by %s (retiring): no confirmation page either way, back to %s/', $kid2, $kid1, DEMO_URL)];

    // 7. The retirement, when due: every JWS the old key signed has expired.
    io()
        ->text('<comment>7.</comment> The old key retires');
    demo_wait_until($retirementDue, sprintf('the retirement window of "%s"', $kid1));
    $retirement = op_console(['heidi:keys:retire', '--due', '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect($retirement->isSuccessful(), 'heidi:keys:retire --due ran (' . trim($retirement->getErrorOutput() . $retirement->getOutput()) . ')');
    $byWhom = str_contains($retirement->getOutput(), 'No key') ? 'by the scheduled step, before the command' : 'by heidi:keys:retire --due';
    $keys = demo_keys();
    demo_expect(($keys[$kid1]['status'] ?? null) === 'retired', sprintf('the key "%s" is retired (%s)', $kid1, $byWhom));
    $published = demo_jwks($issuer, $ca);
    demo_expect(! in_array($kid1, $published, true) && in_array($kid2, $published, true), sprintf('the JWK Set lost "%s" and keeps "%s" (%d key(s): %s)', $kid1, $kid2, count($published), implode(', ', $published)));
    $status = demo_userinfo($issuer, $ca, $sessionA['tokens']['access_token']['raw']);
    demo_expect($status === 401, sprintf('the access token of step 1 is refused at UserInfo (got %d)', $status));
    $verified[] = ['7. heidi:keys:retire --due', sprintf('%s retired %s, out of the JWK Set (%d key(s)); the access token of step 1 gets 401 at UserInfo', $kid1, $byWhom, count($published))];

    // What oidc_login does on an unknown "kid" (OidcSignatureVerifier::getKeys()): a copy older than the
    // max-age is refreshed before any check; a valid copy that lacks the "kid" is refetched once, if it
    // was fetched 60 s ago at least (ROTATION_COOLDOWN), and the verification fails otherwise. Measured on
    // the emergency path, "rotate --now", where the new key signs before any relying party could see it.
    io()
        ->section('What oidc_login does on an unknown "kid"');
    run(['php', 'bin/console', 'cache:pool:clear', 'cache.app'], context: $server->withQuiet());
    $since = new DateTimeImmutable();
    $fourth = [];
    demo_sign_in($fourth, $issuer, $password, $ca);
    $fetched = demo_jwks_fetches($since);
    demo_expect(count($fetched) === 1, sprintf('the demo fetched the JWK Set once, its copy was cold (got %d)', count($fetched)));
    $copy = $fetched[0];
    $kid3 = demo_rotate(['--now']);
    io()
        ->text(sprintf(' <info>✓</info> "%s" signs at once (rotate --now), "%s" is retiring; the copy of the demo, fetched at %s, lacks it and is valid for %d s', $kid3, $kid2, $at($copy), DEMO_ROTATION_JWKS_MAX_AGE));
    $since = new DateTimeImmutable();
    $fifth = [];
    $refused = demo_sign_in_refused($fifth, $issuer, $password, $ca);
    $ageAtRefusal = $since->getTimestamp() - $copy->getTimestamp();
    demo_expect(str_contains($refused, 'signature is invalid'), sprintf('the login fails on the signature, %d s after the copy was fetched (the demo said: %s)', $ageAtRefusal, $refused));
    demo_expect(demo_jwks_fetches($since) === [], 'the demo did not refetch the JWK Set: its copy is younger than the cooldown');
    $fetches[] = ['Warm copy, unknown "kid"', $at($since), sprintf('%d s after the fetch, under the cooldown: no refetch, the login fails ("%s")', $ageAtRefusal, $refused)];
    demo_wait_until($copy->modify(sprintf('+%d seconds', DEMO_ROTATION_COOLDOWN + 1)), 'the refetch cooldown of oidc_login');
    $since = new DateTimeImmutable();
    $sixth = [];
    $sessionD = demo_sign_in($sixth, $issuer, $password, $ca);
    demo_expect($signedBy($sessionD, 'id_token') === $kid3, sprintf('the login succeeds, the ID token names "%s"', $kid3));
    $fetched = demo_jwks_fetches($since);
    $ageAtRefetch = $fetched === [] ? 0 : $fetched[0]->getTimestamp() - $copy->getTimestamp();
    demo_expect(count($fetched) === 1 && $ageAtRefetch < DEMO_ROTATION_JWKS_MAX_AGE, sprintf('the demo refetched the JWK Set once while its copy was still valid (got %d fetch(es), %d s after the copy)', count($fetched), $ageAtRefetch));
    $fetches[] = ['Warm copy, unknown "kid", past the cooldown', $at($fetched[0]), sprintf('%d s after the fetch: one refetch, the new key is in it, the login succeeds', $ageAtRefetch)];

    io()
        ->table(['Step', 'Verified'], $verified);
    io()
        ->table(['JWK Set copy of the demo', 'At (UTC)', 'What oidc_login did'], $fetches);
    demo_rotation_lifetimes($issuer, $ca, false);
    io()
        ->note(sprintf('The OP is left with "%s" active and "%s" retiring until %s, the retirement window of the run; the lifetimes of apps/op/.env are back.', $kid3, $kid2, $at(demo_keys()[$kid2]['retirement_due_at'] ?? new DateTimeImmutable())));
    io()
        ->success('oidc-demo noticed nothing across a scheduled rotation; on an unknown "kid", oidc_login refetches the JWK Set once its copy is 60 s old, and refuses the token before that.');
}

/**
 * Shortens the windows of a rotation in apps/op/.env.local for the run, or removes them: a block the task
 * owns, rewritten every time (a run interrupted before its end leaves it, the next one removes it). The
 * workers of the op container restart on the change (the watch of compose.yaml), the console commands
 * read the file each time; the JWK Set says when the new values serve.
 */
function demo_rotation_lifetimes(string $issuer, string $ca, bool $shorten): void
{
    $path = getcwd() . '/' . DEV_ENV_LOCAL;
    $block = sprintf('/\n*###> %1$s ###\n.*?###< %1$s ###\n/s', preg_quote(DEMO_ROTATION_ENV_MARKER, '/'));
    $content = rtrim((string) preg_replace($block, "\n", (string) file_get_contents($path)), "\n") . "\n";
    if ($shorten) {
        $content .= sprintf("\n###> %1\$s ###\nHEIDI_JWKS_MAX_AGE=%2\$d\nHEIDI_ACCESS_TOKEN_TTL=%3\$d\nHEIDI_ID_TOKEN_TTL=%3\$d\n###< %1\$s ###\n", DEMO_ROTATION_ENV_MARKER, DEMO_ROTATION_JWKS_MAX_AGE, DEMO_ROTATION_TOKEN_TTL);
        // demo_expect() exits, and exit() skips finally blocks: the file is restored whatever ends the run.
        register_shutdown_function(static function () use ($path, $block): void {
            file_put_contents($path, rtrim((string) preg_replace($block, "\n", (string) file_get_contents($path)), "\n") . "\n");
        });
    }
    file_put_contents($path, $content);
    // The worker is the process that dates the retirement of the key it replaces (the longest lifetime of a
    // JWS, read on the issuers of its own container): a consumer reads the file once, at its start.
    run(['docker', 'compose', 'restart', 'worker'], context: context()->withQuiet());
    $deadline = time() + 60;
    do {
        $response = http_request('GET', $issuer . '/jwks', [
            'cafile' => $ca,
        ]);
        $maxAge = preg_match('/max-age=(\d+)/', $response->getHeaders(false)['cache-control'][0] ?? '', $match) === 1 ? (int) $match[1] : null;
        if (($maxAge === DEMO_ROTATION_JWKS_MAX_AGE) === $shorten) {
            io()
                ->text(sprintf(' <info>✓</info> %s %s; the JWK Set announces max-age=%d, the worker restarted', $shorten ? 'wrote the windows of the run into' : 'removed the windows of the run from', DEV_ENV_LOCAL, $maxAge));

            return;
        }
        sleep(1);
    } while (time() < $deadline);
    io()
        ->error(sprintf('The OP still announces max-age=%d on its JWK Set a minute after %s changed: do the workers of the op container watch .env.local (compose.yaml)?', $maxAge, DEV_ENV_LOCAL));
    exit(1);
}

/**
 * The published keys of the tenant, in the order of the JWK Set.
 *
 * @return list<string>
 */
function demo_jwks(string $issuer, string $ca): array
{
    $jwks = json_decode(http_request('GET', $issuer . '/jwks', [
        'cafile' => $ca,
    ])->getContent(), true);

    return array_values(array_map(static fn (array $key): string => (string) $key['kid'], is_array($jwks['keys'] ?? null) ? $jwks['keys'] : []));
}

/**
 * The keys of the tenant with their status and the two dates the run waits for, read from heidi:keys:list.
 *
 * @return array<string, array{status: string, activates_at: ?DateTimeImmutable, retirement_due_at: ?DateTimeImmutable}>
 */
function demo_keys(): array
{
    $output = (string) preg_replace('/\s+/', ' ', op_console(['heidi:keys:list', '--all', '--no-ansi'], context()->withQuiet())->getOutput());
    $keys = [];
    preg_match_all('/Key identifier (\S+) Algorithm \S+ Status (\S+)(.*?)(?=Key identifier|$)/', $output, $matches, \PREG_SET_ORDER);
    foreach ($matches as $match) {
        $date = static fn (string $label) => preg_match('/' . $label . ' (\S+)/', $match[3], $found) === 1 ? new DateTimeImmutable($found[1]) : null;
        $keys[$match[1]] = [
            'status' => $match[2],
            'activates_at' => $date('Activates at'),
            'retirement_due_at' => $date('Retirement due at'),
        ];
    }

    return $keys;
}

/**
 * Runs heidi:keys:rotate on the OP, shows its output, and returns the identifier of the new key.
 *
 * @param array<string> $options
 */
function demo_rotate(array $options): string
{
    $rotated = op_console(['heidi:keys:rotate', ...$options, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect($rotated->isSuccessful(), 'heidi:keys:rotate ran (' . trim($rotated->getErrorOutput() . $rotated->getOutput()) . ')');
    demo_expect(preg_match('/Key identifier\s+(\S+)/', $rotated->getOutput(), $match) === 1, 'heidi:keys:rotate named the new key');

    return $match[1];
}

/**
 * When the demo fetched the JWK Set of the OP since the given instant: the access log of Caddy (op
 * container), the requests on /jwks whose User-Agent is the one of Symfony's HttpClient, which the demo
 * uses (the conformance suite and a browser say otherwise). Caddy logs in UTC.
 *
 * @return list<DateTimeImmutable>
 */
function demo_jwks_fetches(DateTimeImmutable $since): array
{
    $log = run(['docker', 'compose', 'logs', 'op', '--no-log-prefix', '--since', $since->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z')], context: context()->withQuiet())->getOutput();
    $fetches = [];
    foreach (preg_split('/\R/', $log) ?: [] as $line) {
        if (preg_match('/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\t.*handled request\t(\{.*\})$/', $line, $match) !== 1) {
            continue;
        }
        $entry = json_decode($match[2], true);
        if (! is_array($entry) || ($entry['request']['uri'] ?? null) !== '/jwks' || ! str_contains(implode(' ', $entry['request']['headers']['User-Agent'] ?? []), 'Symfony HttpClient')) {
            continue;
        }
        $at = new DateTimeImmutable(str_replace('/', '-', $match[1]), new DateTimeZone('UTC'));
        if ($at >= $since->modify('-1 second')) {
            $fetches[] = $at;
        }
    }

    return $fetches;
}

function demo_wait_until(DateTimeImmutable $when, string $what): void
{
    $seconds = $when->getTimestamp() - time() + 1;
    if ($seconds <= 0) {
        return;
    }
    io()
        ->text(sprintf('   waiting %d s for %s, until %s UTC', $seconds, $what, $when->setTimezone(new DateTimeZone('UTC'))->format('H:i:s')));
    sleep($seconds);
}

/**
 * The status UserInfo gives a bearer access token.
 */
function demo_userinfo(string $issuer, string $ca, string $accessToken): int
{
    return http_request('GET', $issuer . '/userinfo', [
        'cafile' => $ca,
        'auth_bearer' => $accessToken,
    ])->getStatusCode();
}

/**
 * The walk of a browser from /profile of the demo to the callback of the demo, one request at a time (no
 * redirect followed), every step looked at: PKCE S256 in the authorization request, the login page of the
 * OP and its form, "iss" on the callback (RFC 9207). Returns the URL of the callback, for the caller to
 * see what the demo makes of it.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_authenticate(array &$cookies, string $issuer, string $password, string $ca): string
{
    // /profile: the demo starts the flow
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/authorize?'), sprintf('/profile sends the browser to the authorization endpoint (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $authorization);
    demo_expect(($authorization['response_type'] ?? null) === 'code' && ($authorization['code_challenge_method'] ?? null) === 'S256' && ($authorization['client_id'] ?? null) === DEMO_CLIENT_ID, 'the authorization request is response_type=code with PKCE S256');

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

    return $location;
}

/**
 * A sign-in through the demo: the walk to the callback, then the demo exchanges the code, verifies the ID
 * token, reads UserInfo and opens /profile, whose tokens are returned.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 * @return array{page: string, tokens: array<string, array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}>}
 */
function demo_sign_in(array &$cookies, string $issuer, string $password, string $ca): array
{
    $location = demo_authenticate($cookies, $issuer, $password, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/profile', sprintf('the demo signs the user in (got %d %s)', $status, $location));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/profile');
    demo_expect($status === 200, sprintf('/profile opens (got %d)', $status));
    $tokens = demo_tokens_of($page);
    demo_expect(isset($tokens['id_token'], $tokens['access_token']), '/profile shows an ID token and an access token');

    return [
        'page' => $page,
        'tokens' => $tokens,
    ];
}

/**
 * A sign-in the demo refuses at the callback: the browser lands on the failure path of oidc_login, the
 * login page of the demo, which says why. Returns that reason.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_sign_in_refused(array &$cookies, string $issuer, string $password, string $ca): string
{
    $location = demo_authenticate($cookies, $issuer, $password, $ca);
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/login', sprintf('the demo refuses the login and sends the browser to its failure path (got %d %s)', $status, $location));
    [$status, , $page] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/login');
    demo_expect($status === 200 && preg_match('/<code>([^<]+)<\/code>/', $page, $detail) === 1, 'the login page of the demo says why');

    return html_entity_decode($detail[1]);
}

/**
 * RP-Initiated Logout through the demo: /logout ends its session and sends the browser to the end session
 * endpoint of the OP with id_token_hint and post_logout_redirect_uri, the OP ends its session and sends
 * the browser back. Returns the "kid" of the hint, the ID token the session held.
 *
 * @param array<string, array<string, string>> $cookies host => name => value
 */
function demo_logout(array &$cookies, string $issuer, string $ca): string
{
    [$status, $location] = demo_request($cookies, $ca, 'GET', DEMO_URL . '/logout');
    demo_expect($status === 302 && str_starts_with($location, $issuer . '/logout?'), sprintf('/logout sends the browser to the end session endpoint (got %d %s)', $status, $location));
    parse_str((string) parse_url($location, \PHP_URL_QUERY), $logout);
    demo_expect(is_string($logout['id_token_hint'] ?? null) && ($logout['post_logout_redirect_uri'] ?? null) === DEMO_URL . '/', 'the logout request carries id_token_hint and post_logout_redirect_uri');
    [$status, $location] = demo_request($cookies, $ca, 'GET', $location);
    demo_expect($status === 302 && $location === DEMO_URL . '/', sprintf('the OP ends the session and sends the browser back to the demo (got %d %s)', $status, $location));

    return (string) (demo_jwt($logout['id_token_hint'])['header']['kid'] ?? '?');
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
 * (RFC 9068 §2.1), the audience the ID token (OIDC Core §2; the nonce would not do, an ID token issued on
 * a refresh carries none, §12.2).
 *
 * @return array<string, array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}>
 */
function demo_tokens_of(string $page): array
{
    $tokens = [];
    preg_match_all('/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/', $page, $matches);
    foreach (array_unique($matches[0]) as $jwt) {
        $token = demo_jwt($jwt);
        if (($token['header']['typ'] ?? null) === 'at+jwt') {
            $tokens['access_token'] = $token;
        } elseif (isset($token['claims']['aud'], $token['claims']['sub'])) {
            $tokens['id_token'] = $token;
        }
    }

    return $tokens;
}

/**
 * A compact JWS read, not verified: the check looks at what the demo shows, the demo verified it.
 *
 * @return array{raw: string, header: array<string, mixed>, claims: array<string, mixed>}
 */
function demo_jwt(string $jwt): array
{
    [$header, $payload] = explode('.', $jwt) + [
        1 => '',
    ];
    $decode = static fn (string $part): array => (array) json_decode((string) base64_decode(strtr($part, '-_', '+/'), true), true);

    return [
        'raw' => $jwt,
        'header' => $decode($header),
        'claims' => $decode($payload),
    ];
}
