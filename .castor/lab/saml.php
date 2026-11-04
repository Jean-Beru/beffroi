<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;

const SAML_SP_URL = 'https://saml-sp.localhost';

const SAML_SP_ENTITY_ID = SAML_SP_URL . '/simplesaml/module.php/saml/sp/metadata/beffroi';

const SAML_SP_DIRECTORY = 'var/saml-sp';

const SAML_SP_METADATA_FILE = SAML_SP_DIRECTORY . '/metadata/sp-metadata.xml';

const SAML_SP_SOURCES = [
    'beffroi' => SAML_SP_METADATA_FILE,
    'beffroi-encrypted' => SAML_SP_DIRECTORY . '/metadata/sp-encrypted-metadata.xml',
];

const SAML_SP_ENCRYPTION = [
    'content' => 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    'key' => 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
];

const SAML_SP_CAPTURED = SAML_SP_DIRECTORY . '/captured';

/**
 * The MARKER of App\Http\CrossSitePost, copied because the tasks do not load the application.
 */
const SAML_POSTED_AGAIN = '_beffroi_posted_again';

/**
 * The NAME of App\Saml\LogoutChainCookie, copied because the tasks do not load the application.
 */
const SAML_LOGOUT_CHAIN_COOKIE = '__Host-beffroi_saml_logout';

const SAML_SP_ORACLE_REDIRECT = 'tests/saml2-bindings/Fixture/oracle';

const SAML_SP_BINDINGS = [
    'redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'post' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
];

#[AsTask(
    name: 'saml-sp',
    description: 'The SAML identity provider of the stack judged by SimpleSAMLphp 2.5.3.1 (issue #732): the service provider is started on https://saml-sp.localhost, reads the metadata of the provider and is registered at it by a metadata file and "beffroi:saml:service-provider:refresh"; then single sign-on is played in HTTP-Redirect and in HTTP-POST as a browser plays it, as the development user, and the attributes SimpleSAMLphp received are printed. Every AuthnRequest is verified by xmlsec1 or by OpenSSL and Python (the detached signature of the redirect) and accepted by the model; every Response by xmlsec1. Each journey is a browser of its own, which signs in at the provider; the HTTP-POST one then signs in a second time, its request posted from the site of the service provider without the cookie of the provider and posted again by the provider from its own origin, answered without a login (spec/saml.md S-28); then SimpleSAMLphp signs it out (issue #734): its LogoutRequest, verified by OpenSSL and Python, ends the session of the provider, the LogoutResponse comes back signed to its single logout service and SimpleSAMLphp accepts it, the browser is sent to the login when it asks to sign in again, and the same LogoutRequest presented again is refused; then a third browser signed in at SimpleSAMLphp signs out at the end session endpoint of the provider (issue #735): the provider sends SimpleSAMLphp a LogoutRequest, verified by OpenSSL and Python under the certificate of its metadata, SimpleSAMLphp ends its session and answers with a LogoutResponse verified under its own certificate, which, posted from the site of SimpleSAMLphp without the cookie of the provider, the provider posts again from its own origin (spec/saml.md S-28), the provider ends the chain on the page that says the browser is signed out, and the same LogoutResponse presented again is refused',
)]
function saml_sp(
    #[AsOption(description: 'Only start the service provider, read the metadata of the provider and register it: no sign-on')]
    bool $up = false,
    #[AsOption(description: 'Play the HTTP-Redirect binding alone')]
    bool $redirect = false,
    #[AsOption(description: 'Play the HTTP-POST binding alone')]
    bool $post = false,
    #[AsOption(
        description: 'Play the service provider that demands its assertion encrypted, "beffroi-encrypted" (issue #733): the assertion on the wire checked to be encrypted, then decrypted by xmlsec1 before its signature is verified',
    )]
    bool $encrypted = false,
    #[AsOption(description: 'Stop the service provider')]
    bool $stop = false,
): void {
    if ($stop) {
        run(['docker', 'compose', '--profile', 'saml-sp', 'rm', '--stop', '--force', 'saml-sp']);

        return;
    }

    io()->title('SimpleSAMLphp 2.5.3.1 against the SAML identity provider of the stack');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['BEFFROI_ISSUER', 'BEFFROI_DEV_USER_PASSWORD'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));
            exit(1);
        }
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');
    $bindings = $redirect || $post ? array_keys(array_filter(['redirect' => $redirect, 'post' => $post])) : array_keys(SAML_SP_BINDINGS);
    $source = $encrypted ? 'beffroi-encrypted' : 'beffroi';

    io()->section('The service provider');
    $ca = saml_sp_start();

    io()->section('It reads the metadata of the provider');
    $endpoint = saml_sp_reads_the_metadata($issuer, $ca);

    io()->section('The provider registers it');
    saml_sp_register($ca, $source);
    if ($up) {
        io()->success(sprintf('%s serves SimpleSAMLphp, which reads %s/saml/metadata; the provider holds its metadata.', SAML_SP_URL, $issuer));

        return;
    }

    io()->section('The AuthnRequests of the service provider');
    $journeys = [];
    foreach ($bindings as $binding) {
        $journeys[$binding] = saml_sp_requests_sign_on($binding, $ca, $endpoint, $source);
    }
    // Empty again: the service provider plays whatever the metadata say, for whoever uses it by hand.
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    saml_sp_verify_requests($journeys);

    io()->section('Single sign-on at the provider');
    foreach ($journeys as $binding => $journey) {
        $journeys[$binding] = saml_sp_sign_on_at_the_provider($journey, $issuer, $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    }
    if (isset($journeys['post'])) {
        io()->section('A second sign-on in the same browser, its request posted from the site of the service provider');
        saml_sp_sign_on_again($journeys['post'], $issuer, $ca, $endpoint);
    }
    saml_sp_verify_responses($journeys);

    io()->section('Single Logout started by the service provider');
    foreach ($journeys as $binding => $journey) {
        saml_sp_log_out($journey, $issuer, $ca);
    }
    saml_sp_verify_logout_requests($journeys);

    io()->section('Single Logout started by the provider');
    $journey = saml_sp_requests_sign_on('redirect', $ca, $endpoint, $source);
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    $journey['capture'] = 'provider-logout';
    $journey = saml_sp_sign_on_at_the_provider($journey, $issuer, $env['BEFFROI_DEV_USER_PASSWORD'], $ca);
    $answer = saml_sp_logged_out_by_the_provider($journey, $issuer, $ca);
    saml_sp_verify_provider_logout($answer);

    io()->success(sprintf(
        'SimpleSAMLphp signed %s in at %s over %s%s and out again, both ways, and every document that crossed was verified.',
        DEV_USERNAME,
        $issuer,
        implode(' and ', array_map(static fn (string $binding): string => SAML_SP_BINDINGS[$binding], array_keys($journeys))),
        $encrypted ? ', its assertion encrypted' : '',
    ));
}

/**
 * @return string the CA of Caddy
 */
function saml_sp_start(): string
{
    foreach ([SAML_SP_DIRECTORY, SAML_SP_DIRECTORY . '/metadata', SAML_SP_CAPTURED] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    foreach (glob(SAML_SP_CAPTURED . '/*') ?: [] as $file) {
        unlink($file);
    }
    $drawn = ! is_file(SAML_SP_DIRECTORY . '/sp.pem') || ! is_file(SAML_SP_DIRECTORY . '/sp.crt');
    if ($drawn) {
        run([
            'openssl',
            'req',
            '-x509',
            '-newkey',
            'rsa:3072',
            '-nodes',
            '-sha256',
            '-days',
            '3650',
            '-subj',
            '/CN=saml-sp.localhost',
            '-keyout',
            SAML_SP_DIRECTORY . '/sp.pem',
            '-out',
            SAML_SP_DIRECTORY . '/sp.crt',
        ], context: context()->withQuiet());
    }
    // Owner only, so that no other account reads the key: the container reads it as root and hands www-data a copy
    // (compose.yaml).
    chmod(SAML_SP_DIRECTORY . '/sp.pem', 0o600);
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    // A container that copied the key of an earlier pair holds it until it is created again.
    run(['docker', 'compose', '--profile', 'saml-sp', 'up', '-d', '--wait', '--build', ...($drawn ? ['--force-recreate'] : []), 'saml-sp']);

    $ca = caddy_ca(getcwd() . '/' . SAML_SP_DIRECTORY . '/caddy-root.crt');
    // Readable by www-data in the container: a certificate, no secret.
    chmod($ca, 0o644);
    $cookies = [];
    for ($attempt = 0; $attempt < 30; ++$attempt) {
        try {
            [$status] = demo_request($cookies, $ca, 'GET', SAML_SP_ENTITY_ID);
        } catch (HttpClientException) {
            $status = 0;
        }
        if ($status === 200) {
            io()->text(sprintf(' <info>✓</info> %s answers through the Caddy of op', SAML_SP_ENTITY_ID));

            return $ca;
        }
        sleep(1);
    }
    io()->error(sprintf('%s does not answer: "castor start" first, then "docker compose --profile saml-sp logs saml-sp".', SAML_SP_ENTITY_ID));
    exit(1);
}

/**
 * @return array{sso: string, entityId: string}
 */
function saml_sp_reads_the_metadata(string $issuer, string $ca): array
{
    $cookies = [];
    $url = $issuer . '/saml/metadata';
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $url);
    demo_expect($status === 200 && str_contains($document, 'IDPSSODescriptor'), sprintf('%s serves the metadata of the provider (got %d)', $url, $status));
    file_put_contents(SAML_SP_CAPTURED . '/idp-metadata.xml', $document);

    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $published = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService') ?: [] as $service) {
        $published[$service->getAttribute('Binding')] = $service->getAttribute('Location');
    }
    $certificates = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate')
        ?: [] as $certificate) {
        $certificates[] = hash('sha256', (string) base64_decode(preg_replace('/\s+/', '', $certificate->textContent) ?? '', true));
    }

    [$status, , $body] = demo_request($cookies, $ca, 'GET', SAML_SP_URL . '/simplesaml/status.php?idp');
    $read = json_decode($body, true);
    demo_expect(
        $status === 200 && is_array($read),
        sprintf('SimpleSAMLphp reads the metadata of the provider and tells what it holds of it (got %d; "docker compose logs saml-sp" says why not)', $status),
    );
    demo_expect($read['entityId'] === $entityId, sprintf('the entity it holds is %s', $entityId));
    $heldServices = [];
    foreach ($read['singleSignOnService'] as $service) {
        $heldServices[$service['Binding']] = $service['Location'];
    }
    demo_expect(
        $heldServices === $published && count($published) === 2,
        sprintf('its single sign-on service is the one published, for HTTP-Redirect and HTTP-POST: %s', implode(', ', array_unique($published))),
    );
    $heldKeys = array_column($read['keys'], 'sha256');
    demo_expect(
        $certificates !== [] && array_diff($certificates, $heldKeys) === [],
        sprintf('it holds the %d signing certificate(s) of the document, by their SHA-256', count($certificates)),
    );
    demo_expect($read['signAuthnRequest'] === true, 'it signs its requests, as WantAuthnRequestsSigned asks');

    return [
        'sso' => $published[SAML_SP_BINDINGS['redirect']],
        'entityId' => $entityId,
    ];
}

function saml_sp_entity_id(string $source): string
{
    return SAML_SP_URL . '/simplesaml/module.php/saml/sp/metadata/' . $source;
}

function saml_sp_register(string $ca, string $source = 'beffroi'): void
{
    $cookies = [];
    $entityId = saml_sp_entity_id($source);
    $file = SAML_SP_SOURCES[$source];
    [$status, , $metadata] = demo_request($cookies, $ca, 'GET', $entityId);
    demo_expect(
        $status === 200 && str_contains($metadata, 'entityID="' . $entityId . '"') && str_contains($metadata, 'SPSSODescriptor'),
        sprintf('%s serves the metadata of the service provider (got %d)', $entityId, $status),
    );
    file_put_contents($file . '.tmp', $metadata);
    rename($file . '.tmp', $file);
    file_put_contents(SAML_SP_CAPTURED . '/sp-metadata.xml', $metadata);
    io()->text(sprintf(' <info>✓</info> written to %s, which op reads at /saml-sp/%s', $file, basename($file)));

    $refresh = op_console(['beffroi:saml:service-provider:refresh', $entityId], context()->withAllowFailure());
    demo_expect($refresh->isSuccessful(), 'beffroi:saml:service-provider:refresh registers it (its output above says why not)');
}

/**
 * @param array{sso: string, entityId: string} $endpoint
 * @return array{binding: string, source: string, cookies: array<string, array<string, string>>, request: array{method: string, url: string, fields: array<string, string>}, ssoUrl: string}
 */
function saml_sp_requests_sign_on(string $binding, string $ca, array $endpoint, string $source = 'beffroi'): array
{
    // SimpleSAMLphp sends the request over HTTP-Redirect whenever the metadata list it: this file narrows the single
    // sign-on service it sees to the binding being played (docker/saml-sp/metadata/saml20-idp-remote.php).
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', $binding);
    $cookies = [];
    $returnTo = SAML_SP_URL . '/simplesaml/status.php?as=' . $source;
    [$status, $location, $page] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/saml/sp/login/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    $journey = [
        'binding' => $binding,
        'source' => $source,
        'cookies' => $cookies,
        'ssoUrl' => $endpoint['sso'],
    ];
    if ($binding === 'redirect') {
        demo_expect(
            in_array($status, [302, 303], true) && str_starts_with($location, $endpoint['sso'] . '?'),
            sprintf('SimpleSAMLphp redirects the browser to %s (got %d %s)', $endpoint['sso'], $status, substr($location, 0, 120)),
        );
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $query);
        demo_expect(isset($query['SAMLRequest'], $query['SigAlg'], $query['Signature']), 'with a signed query string: SAMLRequest, SigAlg, Signature');
        $inflated = gzinflate((string) base64_decode((string) $query['SAMLRequest'], true));
        demo_expect($inflated !== false, 'whose SAMLRequest is base64 over raw DEFLATE');
        // No newline: the oracle reads the file whole, and one would end the Signature parameter.
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-redirect.url', $location);
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-redirect.xml', $inflated);
        $journey['request'] = [
            'method' => 'GET',
            'url' => $location,
            'fields' => [],
        ];
    } else {
        demo_expect($status === 200, sprintf('SimpleSAMLphp answers with the page that posts the request (got %d)', $status));
        $form = saml_sp_page_form($page);
        demo_expect(
            $form['action'] === $endpoint['sso'] && isset($form['fields']['SAMLRequest']),
            sprintf('which posts SAMLRequest to %s (the form posts to %s)', $endpoint['sso'], $form['action']),
        );
        $document = base64_decode($form['fields']['SAMLRequest'], true);
        demo_expect(
            $document !== false && str_contains($document, 'AuthnRequest') && str_contains($document, 'Signature'),
            'a base64 AuthnRequest carrying its own XML signature',
        );
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-post.xml', $document);
        file_put_contents(SAML_SP_CAPTURED . '/authn-request-post.fields.json', json_encode($form['fields'], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
        $journey['request'] = [
            'method' => 'POST',
            'url' => $form['action'],
            'fields' => $form['fields'],
        ];
    }
    $journey['cookies'] = $cookies;

    return $journey;
}

/**
 * @return array{action: string, fields: array<string, string>}
 */
function saml_sp_page_form(string $page): array
{
    demo_expect(preg_match('/<form\b[^>]*\baction="([^"]*)"/i', $page, $action) === 1, 'the page carries a form');

    return [
        'action' => html_entity_decode($action[1]),
        'fields' => demo_form_fields($page),
    ];
}

/**
 * @param array<string, array{binding: string}> $journeys
 */
function saml_sp_verify_requests(array $journeys): void
{
    if (isset($journeys['redirect'])) {
        io()->text('OpenSSL and Python, the signature over the query string and the message it carries:');
        in_alpine(
            'apk add -q openssl python3 >/dev/null 2>&1 && openssl version && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
            . SAML_SP_DIRECTORY
            . '/sp.crt '
            . SAML_SP_CAPTURED
            . '/authn-request-redirect.url',
            [SAML_SP_ORACLE_REDIRECT, SAML_SP_DIRECTORY . '/sp.crt', SAML_SP_CAPTURED],
        );
    }
    if (isset($journeys['post'])) {
        io()->text('xmlsec1, the signature of the document:');
        saml_sp_xmlsec1();
    }
    io()->text('The model, receiving each request and validating it as the single sign-on service has to:');
    saml_sp_in_phpqa('tests/demo/saml-sp-model.php', SAML_SP_CAPTURED);
}

function saml_sp_xmlsec1(): void
{
    in_alpine(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh '
        . SAML_SP_CAPTURED
        . ' "*.xml"',
        ['tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh', SAML_SP_CAPTURED],
    );
}

function saml_sp_in_phpqa(string $script, string $argument): void
{
    if (! is_file('vendor/autoload.php')) {
        io()->error('The repository is not installed: run "composer install" first.');
        exit(1);
    }
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'XDEBUG_MODE=off',
        '-v',
        getcwd() . ':/project:ro',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', saml2_interop_php_version()),
        'php',
        $script,
        $argument,
    ]);
}

/**
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, request: array{method: string, url: string, fields: array<string, string>}, ssoUrl: string, capture?: string} $journey
 * @return array{binding: string, source: string, cookies: array<string, array<string, string>>, response?: string}
 */
function saml_sp_sign_on_at_the_provider(array $journey, string $issuer, string $password, string $ca, bool $signedIn = false): array
{
    $source = $journey['source'] ?? 'beffroi';
    $cookies = $journey['cookies'];
    $request = $journey['request'];
    $binding = SAML_SP_BINDINGS[$journey['binding']];

    [$status, $location, $page] = demo_request($cookies, $ca, $request['method'], $request['url'], $request['fields']);
    if ($signedIn) {
        demo_expect(
            ! ($status === 302 && strtok($location, '?') === $issuer . '/login'),
            sprintf('the provider answers from the session of the browser, without a login (got %d %s)', $status, substr($location, 0, 120)),
        );
    }
    if ($status === 302 && strtok($location, '?') === $issuer . '/login') {
        [$status, , $login] = demo_request($cookies, $ca, 'GET', $location);
        demo_expect($status === 200, sprintf('the provider takes the browser to its login page (got %d)', $status));
        $login = demo_past_the_address($cookies, $ca, $issuer, $login);
        $form = demo_form_with($login, '_username', 'which carries the form of the password');
        demo_expect(
            preg_match('/name="_csrf_token" value="([^"]+)"/', $form, $csrf) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
            'and its token',
        );
        [$status, $location] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
            '_username' => DEV_USERNAME,
            '_password' => $password,
            '_csrf_token' => $csrf[1],
        ]);
        demo_expect($status === 302, sprintf('the form is accepted (got %d)', $status));
        [$status, $location, $page] = demo_resume($cookies, $ca, $issuer, $location);
    }
    demo_expect($status === 200, sprintf('the provider answers with the page that posts the Response (got %d %s)', $status, substr($location, 0, 120)));
    $form = saml_sp_page_form($page);
    demo_expect(
        $form['action'] === SAML_SP_URL . '/simplesaml/module.php/saml/sp/saml2-acs.php/' . $source && isset($form['fields']['SAMLResponse']),
        sprintf('which posts SAMLResponse to the assertion consumer service of the service provider (it posts to %s)', $form['action']),
    );
    $response = base64_decode($form['fields']['SAMLResponse'], true);
    demo_expect($response !== false, 'a base64 Response');
    $name = sprintf('response-%s.xml', $journey['capture'] ?? $journey['binding']);
    file_put_contents(SAML_SP_CAPTURED . '/' . $name, $response);
    if ($source === 'beffroi-encrypted') {
        saml_sp_encrypted_on_the_wire($response);
    }

    [$status, $location] = demo_request($cookies, $ca, 'POST', $form['action'], $form['fields']);
    demo_expect(
        in_array($status, [302, 303], true) && str_starts_with($location, SAML_SP_URL . '/simplesaml/status.php'),
        sprintf('SimpleSAMLphp accepts it and sends the browser back to where it came from (got %d %s)', $status, substr($location, 0, 120)),
    );
    [$status, , $body] = demo_request($cookies, $ca, 'GET', SAML_SP_URL . '/simplesaml/status.php?as=' . $source);
    $session = json_decode($body, true);
    demo_expect($status === 200 && is_array($session) && ($session['authenticated'] ?? false) === true, 'its session is open');

    $rows = [
        ['NameID', sprintf('%s (%s)', $session['nameId']['value'] ?? '?', $session['nameId']['format'] ?? '?')],
        ['SessionIndex', (string) ($session['sessionIndex'] ?? '?')],
    ];
    foreach ($session['attributes'] as $attribute => $values) {
        $rows[] = [$attribute, implode(', ', $values)];
    }
    io()->text(sprintf('What SimpleSAMLphp received over %s from %s:', $binding, (string) ($session['idp'] ?? '?')));
    io()->table(['', 'Received'], $rows);
    demo_expect($session['attributes'] !== [], 'the assertion carried attributes');

    return [
        'binding' => $journey['binding'],
        'source' => $source,
        'cookies' => $cookies,
        'response' => $name,
    ];
}

/**
 * @param array{source?: string, cookies: array<string, array<string, string>>} $first
 * @param array{sso: string, entityId: string} $endpoint
 */
function saml_sp_sign_on_again(array $first, string $issuer, string $ca, array $endpoint): void
{
    $journey = saml_sp_requests_sign_on('post', $ca, $endpoint, $first['source'] ?? 'beffroi');
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    $provider = (string) parse_url($issuer, \PHP_URL_HOST);
    demo_expect(($first['cookies'][$provider] ?? []) !== [], 'the browser holds the session cookie of the provider since the first sign-on');
    $journey['cookies'][$provider] = $first['cookies'][$provider];
    $journey['request'] = [
        'method' => 'POST',
        ...saml_sp_posted_from_another_site($journey['request']['url'], $journey['request']['fields'], $ca),
    ];
    $journey['capture'] = 'post-again';
    saml_sp_sign_on_at_the_provider($journey, $issuer, '', $ca, signedIn: true);
}

/**
 * A PHP client sends no "Sec-Fetch-Site" and every cookie of its jar, so the cross-site post is written here as a
 * browser writes it.
 *
 * @param array<string, string> $fields
 * @param array<string, string> $sameSiteNone the cookies of the provider a cross-site post carries, by name
 * @return array{url: string, fields: array<string, string>}
 */
function saml_sp_posted_from_another_site(string $url, array $fields, string $ca, array $sameSiteNone = []): array
{
    $headers = [
        'Sec-Fetch-Site' => 'cross-site',
    ];
    if ($sameSiteNone !== []) {
        $headers['Cookie'] = implode('; ', array_map(
            static fn (string $name, string $value): string => $name . '=' . $value,
            array_keys($sameSiteNone),
            array_values($sameSiteNone),
        ));
    }
    $response = http_request('POST', $url, [
        'max_redirects' => 0,
        'cafile' => $ca,
        'headers' => $headers,
        'body' => $fields,
    ]);
    $status = $response->getStatusCode();
    // Less the two cookies the profiler of a stack in debug sets on every answer of a stateful firewall
    // (SecurityDataCollector), which are not the provider's.
    $set = array_values(array_filter(
        array_map(
            static fn (string $cookie): string => trim(explode('=', $cookie, 2)[0]),
            $response->getHeaders(false)['set-cookie'] ?? [],
        ),
        static fn (string $name): bool => preg_match('/_(de)?auth_profile_token$/', $name) !== 1,
    ));
    demo_expect(
        $status === 200 && $set === [],
        sprintf(
            'the provider answers the post that came without its cookie with a page of its own, which sets no cookie (got %d%s)',
            $status,
            $set === [] ? '' : ', setting ' . implode(', ', $set),
        ),
    );
    $form = saml_sp_page_form($response->getContent(false));
    $path = (string) parse_url($url, \PHP_URL_PATH);
    demo_expect(
        $form['action'] === $path . '?' . SAML_POSTED_AGAIN . '=1' && $form['fields'] === $fields,
        sprintf('whose form posts the same fields again to %s, marked so that it is not posted a third time (it posts to %s)', $path, $form['action']),
    );

    return [
        'url' => sprintf(
            '%s://%s%s%s',
            (string) parse_url($url, \PHP_URL_SCHEME),
            (string) parse_url($url, \PHP_URL_HOST),
            parse_url($url, \PHP_URL_PORT) === null ? '' : ':' . parse_url($url, \PHP_URL_PORT),
            $form['action'],
        ),
        'fields' => $form['fields'],
    ];
}

/**
 * @param array<string, array{response?: string}> $journeys
 */
function saml_sp_verify_responses(array $journeys): void
{
    if (array_filter($journeys, static fn (array $journey): bool => isset($journey['response'])) === []) {
        return;
    }
    foreach (glob(SAML_SP_CAPTURED . '/response-*.xml') ?: [] as $file) {
        if (str_contains((string) file_get_contents($file), 'EncryptedAssertion')) {
            saml_sp_decrypt($file);
        }
    }
    io()->text('xmlsec1, the signatures of the Responses:');
    saml_sp_xmlsec1();
}

/**
 * The Algorithm attributes are read, not the text: a random ID, digest or ciphertext holds "cbc" in some runs.
 */
function saml_sp_encrypted_on_the_wire(string $response): void
{
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($response), 'the Response is well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    demo_expect(
        (int) $xpath->evaluate('count(/samlp:Response/saml:EncryptedAssertion)') === 1 && (int) $xpath->evaluate('count(//saml:Assertion)') === 0,
        'its assertion is encrypted: one saml:EncryptedAssertion, no saml:Assertion in clear',
    );
    demo_expect(
        (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)')
            === SAML_SP_ENCRYPTION['content']
        && (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)')
            === SAML_SP_ENCRYPTION['key'],
        sprintf('under %s, its key under %s', SAML_SP_ENCRYPTION['content'], SAML_SP_ENCRYPTION['key']),
    );
    $algorithms = array_map(static fn (DOMAttr $algorithm): string => $algorithm->value, iterator_to_array($xpath->query('//@Algorithm') ?: []));
    demo_expect(
        array_filter($algorithms, static fn (string $algorithm): bool => stripos($algorithm, 'cbc') !== false) === [],
        sprintf('no algorithm of it is in CBC (%s)', implode(', ', array_unique($algorithms))),
    );
}

function saml_sp_decrypt(string $file): void
{
    $assertion = capture(alpine_command(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1'
        . ' && xmlsec1 --decrypt --lax-key-search --privkey-pem '
        . SAML_SP_DIRECTORY
        . '/sp.pem --output /tmp/decrypted.xml '
        . escapeshellarg($file)
        . ' && xmllint --xpath \'/*/*[local-name()="EncryptedAssertion"]/*[local-name()="Assertion"]\' /tmp/decrypted.xml',
        [SAML_SP_DIRECTORY . '/sp.pem', $file],
    ));
    $name = basename($file, '.xml') . '.decrypted-assertion.xml';
    file_put_contents(SAML_SP_CAPTURED . '/' . $name, $assertion);
    demo_expect(
        str_contains($assertion, ':Assertion') && str_contains($assertion, 'Signature'),
        sprintf('xmlsec1 decrypts %s into a signed assertion, %s', basename($file), $name),
    );
}

/**
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, response?: string} $journey
 */
function saml_sp_log_out(array $journey, string $issuer, string $ca): void
{
    $cookies = $journey['cookies'];
    $source = $journey['source'] ?? 'beffroi';
    $returnTo = SAML_SP_URL . '/simplesaml/status.php?as=' . $source;
    [$status, $request] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/core/logout/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    demo_expect(
        in_array($status, [302, 303], true) && strtok($request, '?') === $issuer . '/saml/slo',
        sprintf('SimpleSAMLphp sends the browser to the single logout service of the provider (got %d %s)', $status, substr($request, 0, 120)),
    );
    parse_str((string) parse_url($request, \PHP_URL_QUERY), $query);
    demo_expect(isset($query['SAMLRequest'], $query['SigAlg'], $query['Signature']), 'with a LogoutRequest signed over the query string');
    $inflated = gzinflate((string) base64_decode((string) $query['SAMLRequest'], true));
    demo_expect($inflated !== false, 'whose SAMLRequest is base64 over raw DEFLATE');
    // No newline: the oracle reads the file whole, and one would end the Signature parameter.
    file_put_contents(sprintf('%s/logout-request-%s.url', SAML_SP_CAPTURED, $journey['binding']), $request);
    file_put_contents(sprintf('%s/logout-request-%s.xml', SAML_SP_CAPTURED, $journey['binding']), $inflated);

    [$status, $answer, $page] = demo_request($cookies, $ca, 'GET', $request);
    demo_expect(
        $status === 302 && str_starts_with($answer, SAML_SP_URL . '/simplesaml/module.php/saml/sp/saml2-logout.php/' . $source . '?'),
        sprintf(
            'the provider answers at the single logout service of the metadata of SimpleSAMLphp (got %d %s %s)',
            $status,
            substr($answer, 0, 120),
            $status === 302 ? '' : substr(strip_tags($page), 0, 300),
        ),
    );
    parse_str((string) parse_url($answer, \PHP_URL_QUERY), $query);
    demo_expect(isset($query['SAMLResponse'], $query['SigAlg'], $query['Signature']), 'with a LogoutResponse signed over the query string');
    $response = gzinflate((string) base64_decode((string) $query['SAMLResponse'], true));
    demo_expect($response !== false && str_contains($response, 'urn:oasis:names:tc:SAML:2.0:status:Success'), 'which says Success');
    file_put_contents(sprintf('%s/logout-response-%s.url', SAML_SP_CAPTURED, $journey['binding']), $answer);
    file_put_contents(sprintf('%s/logout-response-%s.xml', SAML_SP_CAPTURED, $journey['binding']), $response);

    [$status, $back] = demo_request($cookies, $ca, 'GET', $answer);
    demo_expect(
        in_array($status, [302, 303], true) && str_starts_with($back, $returnTo),
        sprintf('SimpleSAMLphp accepts the LogoutResponse, its signature verified, and sends the browser back (got %d %s)', $status, substr($back, 0, 120)),
    );
    [$status] = demo_request($cookies, $ca, 'GET', $returnTo);
    demo_expect($status === 401, sprintf('its session is closed (got %d)', $status));

    [$status, $sso] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/saml/sp/login/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    demo_expect(in_array($status, [302, 303], true), sprintf('SimpleSAMLphp asks the provider to sign the browser in again (got %d)', $status));
    [$status, $login] = demo_request($cookies, $ca, 'GET', $sso);
    demo_expect(
        $status === 302 && strtok($login, '?') === $issuer . '/login',
        sprintf('the provider sends the browser to its login: its session has ended (got %d %s)', $status, substr($login, 0, 120)),
    );

    [$status, $replayed] = demo_request($cookies, $ca, 'GET', $request);
    demo_expect(
        $status === 400 && $replayed === '',
        sprintf('the same LogoutRequest presented again is refused, without an answer (got %d %s)', $status, substr($replayed, 0, 120)),
    );
}

/**
 * @param array<string, array{binding: string}> $journeys
 */
function saml_sp_verify_logout_requests(array $journeys): void
{
    $urls = array_map(
        static fn (array $journey): string => sprintf('%s/logout-request-%s.url', SAML_SP_CAPTURED, $journey['binding']),
        array_values($journeys),
    );
    io()->text('OpenSSL and Python, the signature of each LogoutRequest over its query string and the message it carries:');
    in_alpine(
        'apk add -q openssl python3 >/dev/null 2>&1 && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh ' . SAML_SP_DIRECTORY . '/sp.crt '
            . implode(' ', $urls),
        [SAML_SP_ORACLE_REDIRECT, SAML_SP_DIRECTORY . '/sp.crt', SAML_SP_CAPTURED],
    );
}

/**
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, response?: string} $journey
 * @return array{binding: string, url?: string} the URL of its answer when SimpleSAMLphp redirected
 */
function saml_sp_logged_out_by_the_provider(array $journey, string $issuer, string $ca): array
{
    $cookies = $journey['cookies'];
    $source = $journey['source'] ?? 'beffroi';
    $returnTo = SAML_SP_URL . '/simplesaml/status.php?as=' . $source;
    $singleLogout = SAML_SP_URL . '/simplesaml/module.php/saml/sp/saml2-logout.php/' . $source;
    $origin = sprintf(
        '%s://%s%s',
        (string) parse_url($issuer, \PHP_URL_SCHEME),
        (string) parse_url($issuer, \PHP_URL_HOST),
        parse_url($issuer, \PHP_URL_PORT) === null ? '' : ':' . parse_url($issuer, \PHP_URL_PORT),
    );

    saml_sp_participation_recorded($cookies, $ca, $source);

    [$status, , $page] = demo_request($cookies, $ca, 'GET', $issuer . '/logout');
    demo_expect($status === 200, sprintf('the end session endpoint of the provider asks the browser to confirm (got %d)', $status));
    $form = demo_form_with($page, 'confirm', 'with the form of the confirmation');
    demo_expect(str_contains($form, 'name="_token"'), 'and its token');
    demo_expect(preg_match('/action="([^"]+)"/', $form, $action) === 1, 'which posts back to the end session endpoint');
    [$status, $request] = demo_request($cookies, $ca, 'POST', $origin . html_entity_decode($action[1]), [...demo_form_fields($form), 'confirm' => 'yes']);
    demo_expect(
        in_array($status, [302, 303], true) && strtok($request, '?') === $singleLogout,
        sprintf('the confirmed logout sends the browser to the single logout service of SimpleSAMLphp (got %d %s)', $status, substr($request, 0, 120)),
    );
    parse_str((string) parse_url($request, \PHP_URL_QUERY), $query);
    demo_expect(
        isset($query['SAMLRequest'], $query['SigAlg'], $query['Signature']) && ! isset($query['RelayState']),
        'with a LogoutRequest signed over the query string, and no RelayState (S-31)',
    );
    $inflated = gzinflate((string) base64_decode((string) $query['SAMLRequest'], true));
    demo_expect($inflated !== false && str_contains($inflated, 'LogoutRequest'), 'whose SAMLRequest is a LogoutRequest, base64 over raw DEFLATE');
    // No newline: the oracle reads the file whole, and one would end the Signature parameter.
    file_put_contents(SAML_SP_CAPTURED . '/provider-logout-request.url', $request);
    file_put_contents(SAML_SP_CAPTURED . '/provider-logout-request.xml', $inflated);
    [$status, $answer, $page] = demo_request($cookies, $ca, 'GET', $request);
    if ($status === 200) {
        $form = saml_sp_page_form($page);
        demo_expect(
            $form['action'] === $issuer . '/saml/slo' && isset($form['fields']['SAMLResponse']),
            sprintf(
                'SimpleSAMLphp accepts the request and posts its LogoutResponse to the single logout service of the provider (it posts to %s)',
                $form['action'],
            ),
        );
        $response = base64_decode($form['fields']['SAMLResponse'], true);
        demo_expect($response !== false && str_contains($response, 'urn:oasis:names:tc:SAML:2.0:status:Success'), 'which says Success');
        file_put_contents(SAML_SP_CAPTURED . '/sp-logout-response.xml', $response);
        $provider = (string) parse_url($issuer, \PHP_URL_HOST);
        $chain = $cookies[$provider][SAML_LOGOUT_CHAIN_COOKIE] ?? '';
        demo_expect($chain !== '', 'the browser holds the cookie of the chain the provider gave it (S-32)');
        $again = saml_sp_posted_from_another_site($form['action'], $form['fields'], $ca, [SAML_LOGOUT_CHAIN_COOKIE => $chain]);
        $carried = ['POST', $again['url'], $again['fields']];
        $answered = ['binding' => 'post'];
    } else {
        demo_expect(
            in_array($status, [302, 303], true) && strtok($answer, '?') === $issuer . '/saml/slo',
            sprintf(
                'SimpleSAMLphp accepts the request and sends the browser back to the single logout service of the provider (got %d %s %s)',
                $status,
                substr($answer, 0, 120),
                substr(strip_tags($page), 0, 300),
            ),
        );
        parse_str((string) parse_url($answer, \PHP_URL_QUERY), $query);
        demo_expect(isset($query['SAMLResponse'], $query['SigAlg'], $query['Signature']), 'with a LogoutResponse signed over the query string');
        $response = gzinflate((string) base64_decode((string) $query['SAMLResponse'], true));
        demo_expect($response !== false && str_contains($response, 'urn:oasis:names:tc:SAML:2.0:status:Success'), 'which says Success');
        file_put_contents(SAML_SP_CAPTURED . '/sp-logout-response.url', $answer);
        file_put_contents(SAML_SP_CAPTURED . '/sp-logout-response.xml', $response);
        $carried = ['GET', $answer, []];
        $answered = ['binding' => 'redirect', 'url' => $answer];
    }
    [$status] = demo_request($cookies, $ca, 'GET', $returnTo);
    demo_expect($status === 401, sprintf('the session of SimpleSAMLphp is closed (got %d)', $status));

    [$status, $location, $page] = demo_request($cookies, $ca, ...$carried);
    demo_expect(
        $status === 200 && str_contains($page, 'data-logged-out="yes"'),
        sprintf('the provider ends the chain on the page that says the browser is signed out (S-34, got %d %s)', $status, substr($location, 0, 120)),
    );

    [$status, $sso] = demo_request(
        $cookies,
        $ca,
        'GET',
        SAML_SP_URL . '/simplesaml/module.php/saml/sp/login/' . $source . '?ReturnTo=' . rawurlencode($returnTo),
    );
    demo_expect(in_array($status, [302, 303], true), sprintf('SimpleSAMLphp asks the provider to sign the browser in again (got %d)', $status));
    [$status, $login] = demo_request($cookies, $ca, 'GET', $sso);
    demo_expect(
        $status === 302 && strtok($login, '?') === $issuer . '/login',
        sprintf('the provider sends the browser to its login: its session has ended (S-29, got %d %s)', $status, substr($login, 0, 120)),
    );

    [$status, $location] = demo_request($cookies, $ca, ...$carried);
    demo_expect(
        $status === 400 && $location === '',
        sprintf('the same LogoutResponse presented again is refused, without an answer (S-33, got %d %s)', $status, substr($location, 0, 120)),
    );

    return $answered;
}

/**
 * Waits for the row: a worker writes it from the event queue, and the walk may sign out before it does.
 *
 * @param array<string, array<string, string>> $cookies
 */
function saml_sp_participation_recorded(array $cookies, string $ca, string $source): void
{
    [$status, , $body] = demo_request($cookies, $ca, 'GET', SAML_SP_URL . '/simplesaml/status.php?as=' . $source);
    $session = json_decode($body, true);
    $sessionIndex = is_array($session) ? (string) ($session['sessionIndex'] ?? '') : '';
    demo_expect(
        $status === 200 && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $sessionIndex) === 1,
        sprintf('SimpleSAMLphp holds the session index of the assertion, the ID of the session of the provider (got %d %s)', $status, $sessionIndex),
    );
    for ($waited = 0; $waited < 30; ++$waited) {
        $count = op_console(
            ['dbal:run-sql', sprintf("SELECT COUNT(*) AS participants FROM beffroi_saml_session_participant WHERE session_id = '%s'", $sessionIndex)],
            context()->withQuiet()->withAllowFailure(),
        );
        if ($count->isSuccessful() && preg_match('/^\s*([0-9]+)\s*$/m', $count->getOutput(), $rows) === 1 && (int) $rows[1] > 0) {
            demo_expect(true, sprintf(
                'the provider recorded the part of SimpleSAMLphp in the session from the queue of its events, after %d s (S-26)',
                $waited,
            ));

            return;
        }
        sleep(1);
    }
    demo_expect(false, 'the provider recorded the part of SimpleSAMLphp in the session within 30 s (S-26): is the worker consuming the events?');
}

/**
 * @param array{binding: string, url?: string} $answer
 */
function saml_sp_verify_provider_logout(array $answer): void
{
    $dom = new DOMDocument();
    demo_expect($dom->loadXML((string) file_get_contents(SAML_SP_CAPTURED . '/idp-metadata.xml')), 'the metadata of the provider captured are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $certificates = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate')
        ?: [] as $index => $certificate) {
        $file = sprintf('%s/idp-signing-%d.crt', SAML_SP_CAPTURED, $index);
        file_put_contents(
            $file,
            "-----BEGIN CERTIFICATE-----\n"
            . chunk_split((string) preg_replace('/\s+/', '', $certificate->textContent), 64, "\n")
            . "-----END CERTIFICATE-----\n",
        );
        $certificates[] = $file;
    }
    demo_expect($certificates !== [], sprintf('the metadata of the provider publish %d signing certificate(s)', count($certificates)));

    io()->text('OpenSSL and Python, the signature of the LogoutRequest of the provider over its query string and the message it carries:');
    in_alpine(
        'apk add -q openssl python3 >/dev/null 2>&1 && verified=; for certificate in '
        . implode(' ', $certificates)
        . '; do if sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh "$certificate" '
        . SAML_SP_CAPTURED
        . '/provider-logout-request.url; then verified=1; break; fi; done; test -n "$verified"',
        [SAML_SP_ORACLE_REDIRECT, SAML_SP_CAPTURED],
    );
    if ($answer['binding'] === 'redirect') {
        io()->text('OpenSSL and Python, the signature of the LogoutResponse of SimpleSAMLphp over its query string and the message it carries:');
        in_alpine(
            'apk add -q openssl python3 >/dev/null 2>&1 && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
            . SAML_SP_DIRECTORY
            . '/sp.crt '
            . SAML_SP_CAPTURED
            . '/sp-logout-response.url',
            [SAML_SP_ORACLE_REDIRECT, SAML_SP_DIRECTORY . '/sp.crt', SAML_SP_CAPTURED],
        );
    }
    // Captured after saml_sp_verify_responses() decrypted the others, so its assertion is decrypted here for xmlsec1.
    $response = SAML_SP_CAPTURED . '/response-provider-logout.xml';
    if (str_contains((string) file_get_contents($response), 'EncryptedAssertion')) {
        saml_sp_decrypt($response);
    }
    io()->text('xmlsec1, every XML signature captured, the Response of this sign-on and a LogoutResponse that was posted among them:');
    saml_sp_xmlsec1();
}

const SAML_ENTRA_TENANT = '20a6e528-cf9e-4f79-8949-bbd59006eff5';

/**
 * The trailing slash included, as Entra sends it.
 */
const SAML_ENTRA_ENTITY_ID = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/';

/**
 * Sent to the tenant with a domain_hint: the invitation redemption URL and My Apps fall back to a one-time passcode
 * by email.
 */
const SAML_ENTRA_AUTHORIZE = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/oauth2/v2.0/authorize';

/**
 * Azure CLI: a public client every tenant knows, whose redirection URI http://localhost takes any port.
 */
const SAML_ENTRA_SIGN_IN_CLIENT = '04b07795-8ddb-461a-bbee-02f9e1bf7b46';

const SAML_ENTRA_SIGN_IN_REDIRECT = 'http://localhost:65000';

const SAML_ENTRA_DIRECTORY = 'var/saml-entra';

const SAML_ENTRA_RECEIVED = SAML_ENTRA_DIRECTORY . '/received';

/**
 * The trailing slash included, as the Federation Metadata XML of the enterprise application names it.
 */
const SAML_ENTRA_IDP_ENTITY_ID = 'https://sts.windows.net/' . SAML_ENTRA_TENANT . '/';

const SAML_ENTRA_IDP_SINGLE_SIGN_ON = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/saml2';

/**
 * Written by hand in the portal of Entra: a stack under another issuer is a service provider Entra does not know.
 */
const SAML_ENTRA_SP_IDENTIFIER = 'https://op.localhost/saml/sp/metadata';

const SAML_ENTRA_SP_REPLY_URL = 'https://op.localhost/saml/sp/acs';

/**
 * alice is in a group the mapping does not name, bob in the one it maps to "finance".
 */
const SAML_ENTRA_PEOPLE = [
    'alice' => 'alice@beffroilaboutlook.onmicrosoft.com',
    'bob' => 'bob@beffroilaboutlook.onmicrosoft.com',
];

const SAML_ENTRA_GROUP = 'finance';

const SAML_ENTRA_CORPUS = 'tests/saml2-model/Fixture/real';

/**
 * Run by the PHP of the op container, on the profiler storage of its kernel.
 */
const SAML_ENTRA_PROFILE_READER = <<<'PHP'
    <?php

    declare(strict_types=1);

    require '/app/vendor/autoload.php';

    $storage = new Symfony\Component\HttpKernel\Profiler\FileProfilerStorage('file:/app/var/cache/dev/profiler');
    $rows = [];
    foreach (array_slice($argv, 2) as $path) {
        foreach ($storage->find(null, $path, 500, null, (int) $argv[1]) as $row) {
            $rows['t' . $row['token']] = $row;
        }
    }
    $found = [];
    foreach ($rows as $row) {
        $profile = $storage->read((string) $row['token']);
        if ($profile === null || ! $profile->hasCollector('request')) {
            continue;
        }
        $request = $profile->getCollector('request');
        $server = $request->getRequestServer(true)->all();
        $found[] = [
            'token' => (string) $row['token'],
            'time' => $profile->getTime(),
            'method' => $request->getMethod(),
            'url' => $profile->getUrl(),
            'status' => $profile->getStatusCode(),
            'query' => is_string($server['QUERY_STRING'] ?? null) ? $server['QUERY_STRING'] : '',
            'fields' => array_map(
                static fn (mixed $value): mixed => $value instanceof Symfony\Component\VarDumper\Cloner\Data ? $value->getValue(true) : $value,
                $request->getRequestRequest()->all(),
            ),
            'body' => is_string($request->getContent()) ? $request->getContent() : '',
            'secFetchSite' => is_string($server['HTTP_SEC_FETCH_SITE'] ?? null) ? $server['HTTP_SEC_FETCH_SITE'] : null,
        ];
    }
    usort($found, static fn (array $a, array $b): int => $a['time'] <=> $b['time']);
    echo json_encode($found, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    PHP;

#[AsTask(
    name: 'saml-entra',
    description: 'The Entra judge (issue #736): registers the service provider declared for Entra\'s SAML federation of guests, then prints what the portal of Entra takes (Issuer URI, passive authentication endpoint, signing certificate), the invitation Microsoft Graph creates and the authorization request to the tenant, carrying the domain_hint, through which the guest signs in and redeems it; with --received, lists what the provider accepted from the entity ID declared for Entra, read from the profiler of the stack, and writes each document to var/saml-entra/received/ for the corpus. With --upstream (issue #789), Entra the upstream identity provider of the stack: checks the entity ID and the assertion consumer service of the service provider against what the portal holds, refreshes the metadata of the enterprise application, creates the group "finance", plays the walk up to the AuthnRequest sent to Entra, and prints the page to open; with --captured, decodes the request and the response the browser carried into the corpus of saml2-model',
)]
function saml_entra(
    #[AsOption(
        description: 'List what the provider accepted from the entity ID declared for Entra at its single sign-on and single logout services, and write each document to var/saml-entra/received/',
    )]
    bool $received = false,
    #[AsOption(description: 'With --received: how far back the profiles are read, in minutes')]
    int $minutes = 180,
    #[AsOption(description: 'The address the guest is invited with, the email of the user of the provider who signs in')]
    string $email = DEV_USERNAME . '@op.localhost',
    #[AsOption(
        description: 'Entra the upstream identity provider of the stack (issue #789): prepare the provider for a sign-in by hand through oidc-demo, and print the page to open',
    )]
    bool $upstream = false,
    #[AsOption(
        description: 'After a sign-in of --upstream: a file holding what the browser carried, the URL of the request to Entra or the SAMLRequest of its query, the form posted to the assertion consumer service or its SAMLResponse, decoded into tests/saml2-model/Fixture/real/ (repeatable)',
        mode: InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
    )]
    array $captured = [],
): void {
    if ($captured !== []) {
        io()->title('What the browser carried between the stack and Entra, into the corpus');
        saml_entra_corpus(array_values(array_filter($captured, is_string(...))));

        return;
    }
    if ($upstream) {
        io()->title('Entra ID, an identity provider upstream of the stack');
        saml_entra_upstream();

        return;
    }
    io()->title('Entra federating the SAML identity provider of the stack');
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    if (($env['BEFFROI_ISSUER'] ?? '') === '') {
        io()->error('BEFFROI_ISSUER is empty: run "castor provision" first.');
        exit(1);
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');
    foreach ([SAML_ENTRA_DIRECTORY, SAML_ENTRA_RECEIVED] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    if ($received) {
        saml_entra_received($issuer, $minutes);

        return;
    }

    io()->section('The metadata of the provider');
    $ca = caddy_ca(getcwd() . '/' . SAML_ENTRA_DIRECTORY . '/caddy-root.crt');
    $cookies = [];
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $issuer . '/saml/metadata');
    demo_expect($status === 200 && str_contains($document, 'IDPSSODescriptor'), sprintf('%s/saml/metadata serves them (got %d)', $issuer, $status));
    file_put_contents(SAML_ENTRA_DIRECTORY . '/op-idp-metadata.xml', $document);
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document, \LIBXML_NONET), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $singleSignOn = (string) $xpath->evaluate(sprintf(
        'string(/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding="%s"]/@Location)',
        SAML_SP_BINDINGS['post'],
    ));
    demo_expect(
        str_starts_with($singleSignOn, 'https://'),
        sprintf('its single sign-on service over HTTP-POST is %s, in https as Entra requires', $singleSignOn),
    );
    $certificates = [];
    foreach ($xpath->query('/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate')
        ?: [] as $certificate) {
        $certificates[] = (string) preg_replace('/\s+/', '', $certificate->textContent);
    }
    demo_expect($certificates !== [], sprintf('they hold %d signing certificate(s)', count($certificates)));

    io()->section('The provider registers Entra');
    $refresh = op_console(['beffroi:saml:service-provider:refresh', SAML_ENTRA_ENTITY_ID], context()->withAllowFailure());
    demo_expect($refresh->isSuccessful(), sprintf('beffroi:saml:service-provider:refresh registers %s (its output above says why not)', SAML_ENTRA_ENTITY_ID));

    io()->section('What the portal of Entra takes (External Identities, All identity providers, Custom, Add new, SAML/WS-Fed)');
    io()->writeln(sprintf('<comment>Issuer URI</comment> (also the domain_hint):%s%s%s', \PHP_EOL, $entityId, \PHP_EOL));
    io()->writeln(sprintf('<comment>Passive authentication endpoint:</comment>%s%s%s', \PHP_EOL, $singleSignOn, \PHP_EOL));
    foreach ($certificates as $index => $certificate) {
        $file = sprintf('%s/signing-certificate-%d.txt', SAML_ENTRA_DIRECTORY, $index + 1);
        file_put_contents($file, $certificate);
        io()->writeln(sprintf(
            '<comment>Certificate</comment> %d of %d, the base64 of its DER on one line, also in %s (pbcopy < %s):%s%s%s',
            $index + 1,
            count($certificates),
            $file,
            $file,
            \PHP_EOL,
            $certificate,
            \PHP_EOL,
        ));
    }
    if (count($certificates) > 1) {
        io()->warning('The metadata publish more than one signing certificate (a key staged or retiring beside the active one, S-2), and Entra holds one: give it the certificate of the active key, which "castor console beffroi:keys:list" names.');
    }
    io()->writeln(sprintf('<comment>Metadata URL:</comment> empty, Microsoft cannot reach %s.%s', $issuer, \PHP_EOL));
    io()->writeln(sprintf('<comment>Or "Parse metadata file":</comment> %s%s', SAML_ENTRA_DIRECTORY . '/op-idp-metadata.xml', \PHP_EOL));
    $redirect = sprintf('https://myapps.microsoft.com/?tenantid=%s&domain_hint=%s', SAML_ENTRA_TENANT, rawurlencode($entityId));
    io()->writeln(sprintf(
        '<comment>The invitation</comment>, POST https://graph.microsoft.com/v1.0/invitations in Graph Explorer, the portal taking no redirect URL; neither the "inviteRedeemUrl" it answers with nor its "inviteRedirectUrl" sends the browser to the provider, Entra falling back to a one-time passcode:%s%s%s',
        \PHP_EOL,
        json_encode(
            [
                'invitedUserEmailAddress' => $email,
                'inviteRedirectUrl' => $redirect,
                'sendInvitationMessage' => false,
            ],
            \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR,
        ),
        \PHP_EOL,
    ));
    $signIn =
        SAML_ENTRA_AUTHORIZE
        . '?'
        . http_build_query(
            [
                'client_id' => SAML_ENTRA_SIGN_IN_CLIENT,
                'response_type' => 'code',
                'redirect_uri' => SAML_ENTRA_SIGN_IN_REDIRECT,
                'scope' => 'openid',
                'domain_hint' => $entityId,
            ],
            '',
            '&',
            \PHP_QUERY_RFC3986,
        );
    io()->writeln(sprintf(
        '<comment>The sign-in</comment>, opened in the browser by the guest, who signs in at the provider as the user whose email is %s and so redeems the invitation: an authorization request to the tenant, its domain_hint the Issuer URI, for Azure CLI; it ends on an error page of the browser, %s answering nothing, whose address carries the result:%s%s%s',
        $email,
        SAML_ENTRA_SIGN_IN_REDIRECT,
        \PHP_EOL,
        $signIn,
        \PHP_EOL,
    ));
    io()->success(sprintf('%s is registered; once the sign-in is played, "castor saml-entra --received" lists what Entra sent.', SAML_ENTRA_ENTITY_ID));
}

function saml_entra_received(string $issuer, int $minutes): void
{
    io()->section(sprintf('What the provider received from Entra in the last %d minutes', $minutes));
    $read = run(
        ['docker', 'compose', 'exec', '-T', 'op', 'php', '--', (string) (time() - ($minutes * 60)), '/saml/sso', '/saml/slo'],
        context: context()->withInput(SAML_ENTRA_PROFILE_READER)->withQuiet()->withAllowFailure(),
    );
    if (! $read->isSuccessful()) {
        io()->error(sprintf('The profiles of the op container cannot be read: %s', trim($read->getErrorOutput()) ?: '"castor start" first.'));
        exit(1);
    }
    /** @var list<array{token: string, time: int, method: string, url: string, status: int, query: string, fields: array<string, mixed>, body: string, secFetchSite: ?string}> $profiled */
    $profiled = json_decode($read->getOutput(), true, 512, \JSON_THROW_ON_ERROR);
    $received = saml_entra_received_messages($profiled);
    foreach ($received as ['message' => $message, 'requests' => $requests]) {
        $first = $requests[0];
        $base = sprintf('%s/%s-%s-%s', SAML_ENTRA_RECEIVED, date('Ymd\THis', $first['time']), $message['binding'], $message['root']);
        file_put_contents($base . '.xml', $message['document']);
        file_put_contents($base . '.raw.txt', $message['raw']);
        io()->section(saml_entra_text(sprintf('%s, %s over %s', date('c', $first['time']), $message['root'], $message['binding'])));
        io()->listing([
            saml_entra_text(sprintf('Issuer: %s, the entity ID declared', $message['issuer'])),
            saml_entra_text(sprintf('Signed: %s', $message['signed'] ? 'yes' : 'no')),
            ...array_map(
                static fn (array $request): string => saml_entra_text(sprintf(
                    '%s, answered %d, from another site: %s, profile %s/_profiler/%s',
                    saml_entra_posted_again($request) ? 'Posted again from the origin of the provider (S-28)' : 'Received',
                    $request['status'],
                    $request['secFetchSite'] ?? 'not said',
                    $issuer,
                    $request['token'],
                )),
                $requests,
            ),
            ...array_map(
                static fn (string $name, string $value): string => saml_entra_text(sprintf('%s: %s', $name, $value)),
                array_keys($message['facts']),
                array_values($message['facts']),
            ),
            saml_entra_text(sprintf('Written to %s.xml and %s.raw.txt', $base, $base)),
        ]);
        io()->writeln(saml_entra_text($message['document']));
    }
    if ($received === []) {
        io()->warning(sprintf(
            'Nothing the provider accepted from %s was profiled in the last %d minutes: --minutes reads further back; a stack started with --conformance collects no profile.',
            SAML_ENTRA_ENTITY_ID,
            $minutes,
        ));

        return;
    }
    io()->success(sprintf('%d document(s) received from Entra written to %s/: they go to the corpus (issue #665).', count($received), SAML_ENTRA_RECEIVED));
}

/**
 * Entra signs no request: a message counts as Entra's only when its Issuer is exactly the declared entity ID and the
 * provider accepted one of its requests.
 *
 * @param list<array{token: string, time: int, method: string, url: string, status: int, query: string, fields: array<string, mixed>, body: string, secFetchSite: ?string}> $profiled
 * @return list<array{message: array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}, requests: non-empty-list<array{token: string, time: int, method: string, url: string, status: int, query: string, fields: array<string, mixed>, body: string, secFetchSite: ?string}>}>
 */
function saml_entra_received_messages(array $profiled): array
{
    $messages = [];
    foreach ($profiled as $request) {
        $message = saml_entra_message($request);
        if ($message === null || $message['issuer'] !== SAML_ENTRA_ENTITY_ID) {
            continue;
        }
        $digest = hash('sha256', $message['document']);
        $messages[$digest] ??= ['message' => $message, 'requests' => []];
        $messages[$digest]['requests'][] = $request;
    }

    return array_values(array_filter(
        $messages,
        static fn (array $received): bool => array_filter($received['requests'], saml_entra_accepted(...)) !== [],
    ));
}

/**
 * A post from another site without the marker gets 200 from the page that posts it again (S-28), before its message
 * is read.
 *
 * @param array{method: string, url: string, status: int, secFetchSite: ?string} $request
 */
function saml_entra_accepted(array $request): bool
{
    $answeredByThePageThatPostsAgain = $request['method'] === 'POST' && $request['secFetchSite'] === 'cross-site' && ! saml_entra_posted_again($request);

    return ! $answeredByThePageThatPostsAgain && in_array($request['status'], [200, 302], true);
}

/**
 * @param array{url: string} $request
 */
function saml_entra_posted_again(array $request): bool
{
    parse_str((string) parse_url($request['url'], \PHP_URL_QUERY), $query);

    return array_key_exists(SAML_POSTED_AGAIN, $query);
}

/**
 * The value comes from the network: its markup is escaped for the formatter, and every control character but the tab
 * and the line feed, a C1 control included, is written in hexadecimal.
 */
function saml_entra_text(string $value): string
{
    return OutputFormatter::escape((string) preg_replace_callback(
        '/[\x00-\x08\x0B-\x1F\x7F]|\xC2[\x80-\x9F]/',
        static fn (array $control): string => '\\x' . bin2hex($control[0]),
        $value,
    ));
}

/**
 * SAML Bindings §3.4.4.1, §3.5.4
 *
 * @param array{method: string, query: string, fields: array<string, mixed>, body: string} $request
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_message(array $request): ?array
{
    if ($request['method'] === 'GET') {
        parse_str($request['query'], $parameters);

        return saml_entra_message_of('redirect', $request['query'], $parameters);
    }

    return saml_entra_message_of('post', $request['body'], $request['fields']);
}

/**
 * SAML Bindings §3.4.4.1, §3.5.4
 *
 * @param 'redirect'|'post' $binding
 * @param array<array-key, mixed> $parameters
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_message_of(string $binding, string $raw, array $parameters): ?array
{
    $encoded = $parameters['SAMLRequest'] ?? $parameters['SAMLResponse'] ?? null;
    if (! is_string($encoded)) {
        return null;
    }
    $bytes = base64_decode($encoded, true);
    $document = $bytes;
    if ($bytes !== false && $binding === 'redirect') {
        $document = @gzinflate($bytes);
    }
    $dom = new DOMDocument();
    if (! is_string($document) || ! @$dom->loadXML($document, \LIBXML_NONET) || ! $dom->documentElement instanceof DOMElement) {
        return null;
    }
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $root = $dom->documentElement;
    $facts = $root->localName === 'Response' ? saml_entra_response_facts($xpath, $root) : saml_entra_request_facts($xpath, $root);

    return [
        'binding' => $binding,
        'raw' => $raw,
        'document' => $document,
        'root' => $root->localName,
        'issuer' => trim((string) $xpath->evaluate('string(saml:Issuer)', $root)),
        'signed' => isset($parameters['Signature']) || $xpath->query('ds:Signature', $root)?->length > 0,
        'facts' => $facts,
    ];
}

/**
 * @return array<string, string> by attribute of the root, "absent" for one it leaves out
 */
function saml_entra_request_facts(DOMXPath $xpath, DOMElement $root): array
{
    $facts = [];
    foreach (['Destination', 'AssertionConsumerServiceURL', 'AssertionConsumerServiceIndex', 'ProtocolBinding', 'ForceAuthn', 'IsPassive'] as $attribute) {
        $facts[$attribute] = $root->hasAttribute($attribute) ? $root->getAttribute($attribute) : 'absent';
    }
    $policy = $xpath->query('samlp:NameIDPolicy', $root)?->item(0);
    $facts['NameIDPolicy'] = $policy instanceof DOMElement
        ? sprintf('Format %s, AllowCreate %s', $policy->getAttribute('Format') ?: 'absent', $policy->getAttribute('AllowCreate') ?: 'absent')
        : 'absent';
    $contexts = array_map(
        static fn (DOMNode $reference): string => trim($reference->textContent),
        iterator_to_array($xpath->query('samlp:RequestedAuthnContext/saml:AuthnContextClassRef', $root) ?: []),
    );
    $facts['RequestedAuthnContext'] = $xpath->query('samlp:RequestedAuthnContext', $root)?->length
        ? sprintf(
            'Comparison %s, %s',
            $xpath->evaluate('string(samlp:RequestedAuthnContext/@Comparison)', $root) ?: 'absent',
            implode(', ', $contexts) ?: 'no class',
        )
        : 'absent';

    return $facts;
}

/**
 * Never the values of the attributes: only their names and how many values each has.
 *
 * @return array<string, string>
 */
function saml_entra_response_facts(DOMXPath $xpath, DOMElement $root): array
{
    $read = static fn (string $expression): string => trim((string) $xpath->evaluate(sprintf('string(%s)', $expression), $root)) ?: 'absent';
    $count = static fn (string $expression): int => (int) $xpath->evaluate(sprintf('count(%s)', $expression), $root);
    $attributes = [];
    foreach ($xpath->query('saml:Assertion/saml:AttributeStatement/saml:Attribute', $root) ?: [] as $attribute) {
        if ($attribute instanceof DOMElement) {
            $attributes[] = sprintf('%s (%d)', $attribute->getAttribute('Name'), $xpath->query('saml:AttributeValue', $attribute)->length ?? 0);
        }
    }

    return [
        'IssueInstant' => $read('@IssueInstant'),
        'Destination' => $read('@Destination'),
        'InResponseTo' => $read('@InResponseTo'),
        'Status' => $read('samlp:Status/samlp:StatusCode/@Value'),
        'Signature of the Response' => $count('ds:Signature') > 0 ? 'yes' : 'no',
        'Assertion' => match (true) {
            $count('saml:EncryptedAssertion') > 0 => 'encrypted',
            $count('saml:Assertion/ds:Signature') > 0 => 'in clear, signed',
            default => 'in clear, unsigned',
        },
        'NameID' => sprintf('Format %s', $read('saml:Assertion/saml:Subject/saml:NameID/@Format')),
        'AuthnContextClassRef' => $read('saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef'),
        'Conditions' => sprintf('from %s to %s', $read('saml:Assertion/saml:Conditions/@NotBefore'), $read('saml:Assertion/saml:Conditions/@NotOnOrAfter')),
        'Bearer NotOnOrAfter' => $read('saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter'),
        'Attributes, by name and number of values' => implode(', ', $attributes) ?: 'none',
    ];
}

function saml_entra_upstream(): void
{
    $env = load_dot_env(getcwd() . '/apps/op/.env');
    if (($env['BEFFROI_ISSUER'] ?? '') === '') {
        io()->error('BEFFROI_ISSUER is empty: run "castor provision" first.');
        exit(1);
    }
    $issuer = rtrim($env['BEFFROI_ISSUER'], '/');
    $ca = caddy_ca(getcwd() . '/' . SAML_ENTRA_DIRECTORY . '/caddy-root.crt');

    io()->section('The service provider of the tenant, as the portal of Entra holds it');
    $cookies = [];
    [$status, , $document] = demo_request($cookies, $ca, 'GET', $issuer . '/saml/sp/metadata');
    demo_expect($status === 200, sprintf('%s/saml/sp/metadata serves the metadata of the service provider (got %d)', $issuer, $status));
    $dom = new DOMDocument();
    demo_expect($dom->loadXML($document, \LIBXML_NONET), 'which are well-formed XML');
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    $entityId = (string) $xpath->evaluate('string(/md:EntityDescriptor/@entityID)');
    $acs = (string) $xpath->evaluate('string(/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location)');
    demo_expect(
        $entityId === SAML_ENTRA_SP_IDENTIFIER && $acs === SAML_ENTRA_SP_REPLY_URL,
        sprintf(
            'its entity ID %s and its assertion consumer service %s, the Identifier and the Reply URL of the enterprise application',
            $entityId,
            $acs,
        ),
    );

    io()->section('The provider federates Entra');
    $refresh = op_console(['beffroi:saml:identity-provider:refresh', SAML_ENTRA_IDP_ENTITY_ID, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect(
        $refresh->isSuccessful(),
        sprintf(
            'beffroi:saml:identity-provider:refresh reads the Federation Metadata XML of the enterprise application (apps/op/config/saml/entra-enterprise-application-idp.xml)%s',
            $refresh->isSuccessful() ? '' : ': ' . trim($refresh->getOutput() . $refresh->getErrorOutput()),
        ),
    );
    $group = op_console(['beffroi:group:create', SAML_ENTRA_GROUP, '--no-ansi'], context()->withAllowFailure()->withQuiet());
    demo_expect(
        $group->isSuccessful() || str_contains($group->getOutput() . $group->getErrorOutput(), 'already'),
        sprintf('the tenant holds the group "%s", which the object ID of "Lab Finance" maps to (beffroi:group:create)', SAML_ENTRA_GROUP),
    );

    io()->section('The walk up to Entra, and no further');
    $base64url = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    $verifier = $base64url(random_bytes(32));
    $cookies = [];
    [$status, $login] = demo_request(
        $cookies,
        $ca,
        'GET',
        $issuer . '/authorize?'
            . http_build_query([
                'response_type' => 'code',
                'client_id' => DEMO_CLIENT_ID,
                'redirect_uri' => DEMO_URL . '/oidc/callback',
                'scope' => 'openid profile email',
                'state' => $base64url(random_bytes(16)),
                'nonce' => $base64url(random_bytes(16)),
                'code_challenge' => $base64url(hash('sha256', $verifier, true)),
                'code_challenge_method' => 'S256',
            ]),
    );
    demo_expect(
        $status === 302 && str_starts_with($login, $issuer . '/login?interaction='),
        sprintf('oidc-demo asks for an authorization, and the provider asks for a login (got %d %s)', $status, substr($login, 0, 120)),
    );
    [$status, , $page] = demo_request($cookies, $ca, 'GET', $login);
    $form = $status === 200 ? demo_form_with($page, '_address', 'the login page asks for the address first') : '';
    demo_expect(
        preg_match('/name="_token" value="([^"]+)"/', $form, $token) === 1 && preg_match('/action="([^"]+)"/', $form, $action) === 1,
        'its form: one field, its token, where it posts',
    );
    [$status, $signOn] = demo_request($cookies, $ca, 'POST', $issuer . html_entity_decode($action[1]), [
        '_address' => SAML_ENTRA_PEOPLE['alice'],
        '_token' => $token[1],
    ]);
    parse_str((string) parse_url($signOn, \PHP_URL_QUERY), $query);
    demo_expect(
        $status === 303
        && str_starts_with($signOn, $issuer . '/saml/sp/sign-on?')
        && ($query['identity_provider'] ?? null) === SAML_ENTRA_IDP_ENTITY_ID
        && is_string($query['reference'] ?? null)
        && preg_match('/^[A-Za-z0-9_-]{43}$/', $query['reference']) === 1,
        sprintf(
            '%s is sent to the sign-on of Entra, under the one-time reference the login page drew for it, spec/saml.md S-51 (got %d %s)',
            SAML_ENTRA_PEOPLE['alice'],
            $status,
            substr($signOn, 0, 160),
        ),
    );
    [$status, $location] = demo_request($cookies, $ca, 'GET', $signOn);
    demo_expect(
        $status === 302 && str_starts_with($location, SAML_ENTRA_IDP_SINGLE_SIGN_ON . '?'),
        sprintf('the sign-on sends the browser to the single sign-on service of Entra over HTTP-Redirect (got %d %s)', $status, substr($location, 0, 120)),
    );
    $raw = (string) parse_url($location, \PHP_URL_QUERY);
    parse_str($raw, $parameters);
    $request = saml_entra_message_of('redirect', $raw, $parameters);
    demo_expect(
        $request !== null && $request['root'] === 'AuthnRequest' && isset($parameters['SigAlg'], $parameters['Signature'], $parameters['RelayState']),
        'an AuthnRequest, signed over the query string, with a RelayState',
    );
    demo_expect(
        ($parameters['login_hint'] ?? null) === SAML_ENTRA_PEOPLE['alice'] && str_ends_with($raw, '&login_hint=' . rawurlencode(SAML_ENTRA_PEOPLE['alice'])),
        sprintf(
            'the address typed, %s, in the login_hint Entra prefills its sign-in with, after the Signature (spec/saml.md S-68)',
            SAML_ENTRA_PEOPLE['alice'],
        ),
    );
    demo_expect(
        $request['issuer'] === SAML_ENTRA_SP_IDENTIFIER && $request['facts']['AssertionConsumerServiceURL'] === SAML_ENTRA_SP_REPLY_URL,
        sprintf(
            'its Issuer and its AssertionConsumerServiceURL are the Identifier and the Reply URL Entra holds (%s, %s)',
            $request['issuer'],
            $request['facts']['AssertionConsumerServiceURL'],
        ),
    );
    io()->listing(array_map(
        static fn (string $name, string $value): string => saml_entra_text(sprintf('%s: %s', $name, $value)),
        array_keys($request['facts']),
        array_values($request['facts']),
    ));
    io()->text('Not sent: the sign-in at Entra is played by hand.');

    io()->section('The sign-in, by hand');
    io()->listing([
        sprintf('"castor demo" serves oidc-demo on %s ("--dir" names its checkout when it is not next to this one).', DEMO_URL),
        sprintf('In a private window, open %s/profile: the login page of the provider asks for the address, %s.', DEMO_URL, SAML_ENTRA_PEOPLE['alice']),
        'Entra shows its sign-in with her address filled in (login_hint, spec/saml.md S-68), signs her in, then posts its response to the provider, which creates her and answers oidc-demo: /profile shows email, given_name and family_name under "Standard claims", and amr under "ID token".',
        sprintf('Then bob, in another private window, %s: Entra holds the session of alice in the first one.', SAML_ENTRA_PEOPLE['bob']),
        sprintf(
            '"castor console beffroi:user:show <address>" says what the provider holds of each, its source, and bob in the group "%s".',
            SAML_ENTRA_GROUP,
        ),
        'In the network panel, the URL of the request to login.microsoftonline.com and the SAMLResponse posted to /saml/sp/acs, each saved to a file, are decoded into the corpus by "castor saml-entra --captured <file> --captured <file>".',
    ]);
    io()->success(sprintf('%s federates Entra; open %s/profile.', $issuer, DEMO_URL));
}

/**
 * A file of the corpus is never written over with other bytes.
 *
 * @param list<string> $files
 */
function saml_entra_corpus(array $files): void
{
    $written = [];
    foreach ($files as $file) {
        io()->section(saml_entra_text($file));
        $contents = is_file($file) ? file_get_contents($file) : false;
        if (! is_string($contents)) {
            io()->error(sprintf('%s cannot be read.', $file));
            exit(1);
        }
        $message = saml_entra_captured_message($contents);
        if ($message === null) {
            io()->error('It carries no SAMLRequest or SAMLResponse that decodes to XML: the URL of the request, its query, the form posted, or the value of the field alone.');
            exit(1);
        }
        $date = preg_match('/\bIssueInstant="(\d{4}-\d{2}-\d{2})T/', $message['document'], $issued) === 1 ? $issued[1] : null;
        if ($date === null) {
            io()->error(sprintf('Its %s carries no IssueInstant to date it by.', $message['root']));
            exit(1);
        }
        $documents = match (true) {
            $message['root'] === 'AuthnRequest' && $message['issuer'] === SAML_ENTRA_SP_IDENTIFIER => array_filter(
                [
                    sprintf('beffroi-sp-authnrequest-to-entra-%s.xml', $date) => $message['document'],
                    sprintf('beffroi-sp-authnrequest-to-entra-query-%s.txt', $date) =>
                        $message['binding'] === 'redirect' && $message['raw'] !== '' ? $message['raw'] : null,
                ],
                is_string(...),
            ),
            $message['root'] === 'Response' && $message['issuer'] === SAML_ENTRA_IDP_ENTITY_ID => array_filter(
                [
                    sprintf('entra-idp-response-%s-%s.xml', saml_entra_coverage($message['facts']), $date) => $message['document'],
                    sprintf('entra-idp-assertion-%s.xml', $date) => saml_entra_assertion_of($message['document']),
                ],
                is_string(...),
            ),
            default => null,
        };
        if ($documents === null) {
            io()->error(saml_entra_text(sprintf(
                'A %s from %s is neither the AuthnRequest of %s nor the Response of %s.',
                $message['root'],
                $message['issuer'],
                SAML_ENTRA_SP_IDENTIFIER,
                SAML_ENTRA_IDP_ENTITY_ID,
            )));
            exit(1);
        }
        io()->listing([
            saml_entra_text(sprintf('%s from %s, over %s', $message['root'], $message['issuer'], $message['binding'])),
            ...array_map(
                static fn (string $name, string $value): string => saml_entra_text(sprintf('%s: %s', $name, $value)),
                array_keys($message['facts']),
                array_values($message['facts']),
            ),
        ]);
        foreach ($documents as $name => $bytes) {
            $path = SAML_ENTRA_CORPUS . '/' . $name;
            if (is_file($path) && file_get_contents($path) !== $bytes) {
                io()->error(sprintf('%s holds another capture of that day: a document enters the corpus once; remove it first to replace it.', $path));
                exit(1);
            }
            file_put_contents($path, $bytes);
            $written[] = $path;
        }
        if ($message['root'] === 'Response' && ! array_key_exists(sprintf('entra-idp-assertion-%s.xml', $date), $documents)) {
            io()->warning('Its assertion does not stand as a document of its own (encrypted, or a prefix the response declares): only the response is written.');
        }
    }
    io()->listing($written);
    io()->success('Written to the corpus, not committed: each enters it with its row in tests/saml2-model/Unit/RealDocumentsTest.php and its line in spec/model.md section 9.4 (issue #665).');
}

/**
 * The binding is read from the bytes: a message that is XML once its base64 is decoded was posted, any other was
 * deflated (SAML Bindings §3.4.4.1, §3.5.4).
 *
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_captured_message(string $contents): ?array
{
    $contents = trim($contents);
    if (preg_match('/(?:^|[?&])SAML(?:Request|Response)=/', $contents) === 1) {
        $raw = str_contains($contents, '?') ? substr($contents, strpos($contents, '?') + 1) : $contents;
        $raw = explode('#', $raw, 2)[0];
        parse_str($raw, $parameters);
    } else {
        $raw = '';
        $parameters = ['SAMLResponse' => str_contains($contents, '%') ? rawurldecode($contents) : $contents];
    }
    foreach (['SAMLRequest', 'SAMLResponse'] as $name) {
        if (is_string($parameters[$name] ?? null)) {
            // Base64 holds no space: a space is a "+" that a form decoding took for one.
            $parameters[$name] = (string) preg_replace('/[\r\n\t]/', '', strtr($parameters[$name], ' ', '+'));
        }
    }
    $encoded = $parameters['SAMLRequest'] ?? $parameters['SAMLResponse'] ?? null;
    $bytes = is_string($encoded) ? base64_decode($encoded, true) : false;
    if ($bytes === false) {
        return null;
    }
    $posted = str_starts_with(ltrim(str_starts_with($bytes, "\u{FEFF}") ? substr($bytes, 3) : $bytes), '<');

    return saml_entra_message_of($posted ? 'post' : 'redirect', $raw, $parameters);
}

/**
 * @param array<string, string> $facts
 */
function saml_entra_coverage(array $facts): string
{
    $response = ($facts['Signature of the Response'] ?? '') === 'yes';
    $assertion = ($facts['Assertion'] ?? '') === 'in clear, signed';

    return match (true) {
        $response && $assertion => 'signed-both',
        $response => 'signed-response',
        $assertion => 'signed-assertion',
        default => 'unsigned',
    };
}

/**
 * Entra declares the namespace of the assertion on the assertion itself, so that its bytes stand as a document of
 * their own.
 */
function saml_entra_assertion_of(string $response): ?string
{
    if (preg_match('~<((?:[A-Za-z_][\w.-]*:)?)Assertion\b.*</\1Assertion>~s', $response, $matches) !== 1) {
        return null;
    }
    $dom = new DOMDocument();
    if (! @$dom->loadXML($matches[0], \LIBXML_NONET) || ! $dom->documentElement instanceof DOMElement) {
        return null;
    }

    return $dom->documentElement->namespaceURI === 'urn:oasis:names:tc:SAML:2.0:assertion' && $dom->documentElement->localName === 'Assertion'
        ? $matches[0]
        : null;
}
