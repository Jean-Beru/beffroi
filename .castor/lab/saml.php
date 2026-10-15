<?php

declare(strict_types=1);

/*
 * The SAML identity provider of the stack judged by a service provider that is not this project's (sub-spike 9c, issue
 * #732): SimpleSAMLphp 2.5.3.1, the service provider of the judges of 9b (tests/saml2-bindings/Interop/simplesamlphp),
 * served on https://saml-sp.localhost by the "saml-sp" service of compose.yaml behind the Caddy of op, configured with
 * the metadata the stack serves and nothing else (docker/saml-sp/), and registered at the provider the way an
 * operator registers one: its metadata given as a file the development configuration declares
 * (apps/op/config/packages/beffroi.yaml, beffroi.saml.service_providers) and read by "beffroi:saml:service-provider:refresh".
 *
 * Three things judge what the walk captures, none of them the provider and none of them SimpleSAMLphp's reading of
 * itself: xmlsec1 on every XML signature (the AuthnRequest posted, the Response), the OpenSSL command line and Python's
 * zlib on the signature and the message of the AuthnRequest redirected, which carries a detached signature over the
 * query string and none in the XML (the oracles of 9b), and the model of the packages the provider is built on, which
 * receives and validates each AuthnRequest as the single sign-on service has to (tests/demo/saml-sp-model.php).
 *
 * The walk is the browser, as the walks of demo.php are: one request at a time, no redirect followed, a cookie jar per
 * host, the page of the provider read with the eyes of a person. Every document it captures goes to var/saml-sp/captured/.
 *
 * With --encrypted (issue #733, spec/saml.md S-19 to S-21), the walk plays the second service provider of the same
 * SimpleSAMLphp, "beffroi-encrypted": its configuration sets "assertion.encryption", so that it refuses an assertion in
 * clear, and its declaration in apps/op/config/packages/beffroi.yaml sets "encrypt_assertions". The Response captured is
 * checked to carry its assertion encrypted, under aes256-gcm and rsa-oaep-mgf1p and nothing in CBC; xmlsec1 decrypts it
 * under var/saml-sp/sp.pem, and the assertion it gives back joins the documents saml_sp_verify_responses() verifies, its
 * signature under the metadata of the provider, as the signature of the Response over the ciphertext is.
 *
 * Single Logout is played both ways. SimpleSAMLphp starts it on each journey (issue #734, saml_sp_log_out()); then a
 * third browser, signed in at SimpleSAMLphp over HTTP-Redirect, signs out at the end session endpoint of the provider
 * and confirms (issue #735, spec/saml.md S-29 to S-34, saml_sp_logged_out_by_the_provider()): the provider sends
 * SimpleSAMLphp a LogoutRequest, which SimpleSAMLphp verifies under the metadata of the provider (validate.logout) and
 * answers once it has ended its own session, and the provider ends the chain on the page that says the browser is
 * signed out. The LogoutRequest is verified by OpenSSL and Python under the certificate of the metadata of the
 * provider, and the LogoutResponse under the certificate of SimpleSAMLphp, by their oracle when it is redirected and by
 * xmlsec1 when it is posted.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\http_request;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;

const SAML_SP_URL = 'https://saml-sp.localhost';

/**
 * The entity ID of the service provider, as its own metadata carry it and as beffroi.saml.service_providers declares it.
 */
const SAML_SP_ENTITY_ID = SAML_SP_URL . '/simplesaml/module.php/saml/sp/metadata/beffroi';

/**
 * Under the ignored var/ of the repository: the key and the certificate of the service provider and the binding it is
 * asked to play (mounted into the saml-sp service), the metadata the provider reads (mounted into op and worker), and
 * every document of a run.
 */
const SAML_SP_DIRECTORY = 'var/saml-sp';

const SAML_SP_METADATA_FILE = SAML_SP_DIRECTORY . '/metadata/sp-metadata.xml';

/**
 * The two service providers of the one SimpleSAMLphp, by the name of their authentication source
 * (docker/saml-sp/config/authsources.php), and the file the metadata of each are written to, which the declaration of
 * each in apps/op/config/packages/beffroi.yaml names: "beffroi" takes its assertion in clear, "beffroi-encrypted"
 * demands it encrypted (issue #733).
 */
const SAML_SP_SOURCES = [
    'beffroi' => SAML_SP_METADATA_FILE,
    'beffroi-encrypted' => SAML_SP_DIRECTORY . '/metadata/sp-encrypted-metadata.xml',
];

/**
 * What the encrypted assertion is encrypted under (spec/saml.md S-20), as the EncryptionMethod elements name it.
 */
const SAML_SP_ENCRYPTION = [
    'content' => 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    'key' => 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
];

const SAML_SP_CAPTURED = SAML_SP_DIRECTORY . '/captured';

/**
 * The bindings the AuthnRequest travels over, by the name the walk and its files give them, and the value of
 * "Binding" in the metadata that name stands for.
 */
const SAML_SP_BINDINGS = [
    'redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'post' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
];

#[AsTask(
    name: 'saml-sp',
    description: 'The SAML identity provider of the stack judged by SimpleSAMLphp 2.5.3.1 (issue #732): the service provider is started on https://saml-sp.localhost, reads the metadata of the provider and is registered at it by a metadata file and "beffroi:saml:service-provider:refresh"; then single sign-on is played in HTTP-Redirect and in HTTP-POST as a browser plays it, as the development user, and the attributes SimpleSAMLphp received are printed. Every AuthnRequest is verified by xmlsec1 or by OpenSSL and Python (the detached signature of the redirect) and accepted by the model; every Response by xmlsec1. Each journey is a browser of its own, which signs in at the provider; the HTTP-POST one then signs in a second time, its request posted from the site of the service provider without the cookie of the provider and posted again by the provider from its own origin, answered without a login (spec/saml.md S-28); then SimpleSAMLphp signs it out (issue #734): its LogoutRequest, verified by OpenSSL and Python, ends the session of the provider, the LogoutResponse comes back signed to its single logout service and SimpleSAMLphp accepts it, the browser is sent to the login when it asks to sign in again, and the same LogoutRequest presented again is refused; then a third browser signed in at SimpleSAMLphp signs out at the end session endpoint of the provider (issue #735): the provider sends SimpleSAMLphp a LogoutRequest, verified by OpenSSL and Python under the certificate of its metadata, SimpleSAMLphp ends its session and answers with a LogoutResponse verified under its own certificate, the provider ends the chain on the page that says the browser is signed out, and the same LogoutResponse presented again is refused',
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
    // the service provider goes back to playing whatever the metadata say, for whoever uses it by hand
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
 * The service provider up, behind Caddy, with a key and a certificate of its own.
 *
 * The pair is drawn here and not committed, as the client certificate of the stack is not: what a development stack
 * generates stays under var/. It is the pair its metadata carry, and the one every signature of its requests is
 * verified under.
 *
 * @return string the CA of Caddy, with which every request of the walk verifies the certificates of the stack
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
    if (! is_file(SAML_SP_DIRECTORY . '/sp.pem') || ! is_file(SAML_SP_DIRECTORY . '/sp.crt')) {
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
        // read by www-data in the container, the file belonging to whoever runs the task
        chmod(SAML_SP_DIRECTORY . '/sp.pem', 0o644);
    }
    file_put_contents(SAML_SP_DIRECTORY . '/sso-binding', '');
    run(['docker', 'compose', '--profile', 'saml-sp', 'up', '-d', '--wait', '--build', 'saml-sp']);

    $ca = caddy_ca(getcwd() . '/' . SAML_SP_DIRECTORY . '/caddy-root.crt');
    // read by www-data in the container, as the key above
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
 * What SimpleSAMLphp made of the metadata of the provider, compared with the document itself: the same entity, the same
 * two bindings at the same URL, the same keys. Kept for the verifications that follow, with the document.
 *
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

/**
 * The entity ID of a service provider of the SimpleSAMLphp, by its authentication source, as its own metadata carry it
 * and as beffroi.saml.service_providers declares it.
 */
function saml_sp_entity_id(string $source): string
{
    return SAML_SP_URL . '/simplesaml/module.php/saml/sp/metadata/' . $source;
}

/**
 * The metadata of the service provider written where the development configuration says the provider reads them, then
 * registered with the console command a deployment uses: the same object the schedule runs every hour.
 */
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
 * The first half of a journey: the browser asks the service provider to sign it in, and keeps the AuthnRequest the
 * service provider gives it for the provider, in the binding the metadata the service provider reads were narrowed
 * to. Nothing is sent to the provider: that is the next section's, and what is captured here is verified first.
 *
 * @param array{sso: string, entityId: string} $endpoint
 * @return array{binding: string, source: string, cookies: array<string, array<string, string>>, request: array{method: string, url: string, fields: array<string, string>}, ssoUrl: string}
 */
function saml_sp_requests_sign_on(string $binding, string $ca, array $endpoint, string $source = 'beffroi'): array
{
    // SimpleSAMLphp sends the request to the HTTP-Redirect service whenever the metadata list one: the file narrows the
    // single sign-on service it sees to the binding being played (docker/saml-sp/metadata/saml20-idp-remote.php)
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
        // no newline: the oracle of 9b reads the file whole, and one would end the Signature parameter
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
 * The form of a page that posts a document, as a browser reads it: where it posts and the hidden fields it carries.
 *
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
 * Every AuthnRequest of the journeys, by the three judges that are not the provider's: the OpenSSL command line and
 * Python's zlib on the detached signature and the message of the redirect, xmlsec1 on the XML signature of the post,
 * the model on both, received by the receiver of their binding.
 *
 * @param array<string, array{binding: string}> $journeys
 */
function saml_sp_verify_requests(array $journeys): void
{
    if (isset($journeys['redirect'])) {
        io()->text('OpenSSL and Python, the signature over the query string and the message it carries:');
        in_alpine('apk add -q openssl python3 >/dev/null 2>&1 && openssl version && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
        . SAML_SP_DIRECTORY
        . '/sp.crt '
        . SAML_SP_CAPTURED
        . '/authn-request-redirect.url');
    }
    if (isset($journeys['post'])) {
        io()->text('xmlsec1, the signature of the document:');
        saml_sp_xmlsec1();
    }
    io()->text('The model, receiving each request and validating it as the single sign-on service has to:');
    saml_sp_in_phpqa('tests/demo/saml-sp-model.php', SAML_SP_CAPTURED);
}

/**
 * xmlsec1 on every XML signature of the documents captured, each under the certificate of the metadata of its signer,
 * both metadata documents being among them (tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh): a document
 * with no XML signature, the redirected request, is listed and skipped.
 */
function saml_sp_xmlsec1(): void
{
    in_alpine('apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh '
    . SAML_SP_CAPTURED
    . ' "*.xml"');
}

/**
 * A script of the repository in the phpqa image, which has the dependencies of the monorepo the script loads.
 */
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
 * The second half of a journey, at the provider: the AuthnRequest the browser holds sent to the single sign-on service,
 * the login of the development user, the Response the provider posts back, carried to the assertion consumer service of
 * the service provider, and what SimpleSAMLphp holds of its session afterwards.
 *
 * Each journey is a browser of its own and signs in: the request waits for the login in the session of that browser
 * (spec/saml.md S-18) and is resumed into the page that posts the Response, in the binding the metadata name for it
 * (HTTP-POST, SAML Bindings §3.5).
 *
 * A browser already signed in at the provider ($signedIn) is answered from its session, and the login is then a
 * failure of the journey; the Response it is answered with is captured under the name of the journey ($journey['capture']).
 *
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
    // the login every page of the provider that is not an authorization request sends the browser to, its path read
    // and not its query (spec/saml.md S-18)
    if ($status === 302 && strtok($location, '?') === $issuer . '/login') {
        [$status, , $login] = demo_request($cookies, $ca, 'GET', $location);
        demo_expect($status === 200, sprintf('the provider takes the browser to its login page (got %d)', $status));
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
 * A second sign-on in the browser of the HTTP-POST journey, signed in at the provider by the first (spec/saml.md S-28,
 * issue #739): the service provider posts a new AuthnRequest from its own site, which a "SameSite=Lax" session cookie
 * does not accompany, and the provider answers with a page of its own origin that posts the same fields again, once,
 * from where the cookie comes with them; that post is answered from the session, without a login.
 *
 * The walk is a PHP client and not a browser: it sends no "Sec-Fetch-Site" and carries every cookie of its jar, whatever
 * "SameSite" says. So the cross-site post is written here as a browser writes it, "Sec-Fetch-Site: cross-site" and no
 * cookie of the provider, and what the walk proves is the answer of the provider to that post, the page and the post
 * again; that a browser keeps the cookie back is the browser's, which the walk does not play.
 *
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
    $request = $journey['request'];

    $response = http_request('POST', $request['url'], [
        'max_redirects' => 0,
        'cafile' => $ca,
        'headers' => [
            'Sec-Fetch-Site' => 'cross-site',
        ],
        'body' => $request['fields'],
    ]);
    $status = $response->getStatusCode();
    // the cookies the page sets, less the two the profiler of a stack in debug sets on every answer of a firewall
    // that is not stateless, to link the profiles of a sign-in and a sign-out (SecurityDataCollector): they are the
    // instrumentation's, not the provider's, and no stack that collects no profile sets them
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
    $path = (string) parse_url($request['url'], \PHP_URL_PATH);
    demo_expect(
        $form['action'] === $path . '?_beffroi_posted_again=1' && $form['fields'] === $request['fields'],
        sprintf('whose form posts the same fields again to %s, marked so that it is not posted a third time (it posts to %s)', $path, $form['action']),
    );

    $journey['request'] = [
        'method' => 'POST',
        'url' => sprintf(
            '%s://%s%s%s',
            (string) parse_url($request['url'], \PHP_URL_SCHEME),
            (string) parse_url($request['url'], \PHP_URL_HOST),
            parse_url($request['url'], \PHP_URL_PORT) === null ? '' : ':' . parse_url($request['url'], \PHP_URL_PORT),
            $form['action'],
        ),
        'fields' => $form['fields'],
    ];
    $journey['capture'] = 'post-again';
    saml_sp_sign_on_at_the_provider($journey, $issuer, '', $ca, signedIn: true);
}

/**
 * xmlsec1 on every signature of the Responses the provider posted, under the certificate its metadata publish, and the
 * requests again beside them.
 *
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
 * The acceptance of issue #733 on the wire (spec/saml.md S-19, S-20): the Response carries one saml:EncryptedAssertion
 * and no assertion in clear, its content under aes256-gcm and its key under rsa-oaep-mgf1p, and no algorithm of it in
 * CBC. The algorithms are what is read, the Algorithm of every element that names one, and not the text of the
 * document: an ID, a digest or a ciphertext is hexadecimal or base64 drawn at random, and holds "cbc" in some runs.
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

/**
 * xmlsec1, which is not the provider and not SimpleSAMLphp, decrypts the assertion of a Response captured with the
 * private key of the service provider, and the assertion it gives back is written beside it, so that
 * saml_sp_xmlsec1() verifies its signature as a document of its own.
 */
function saml_sp_decrypt(string $file): void
{
    $assertion = capture([
        'docker',
        'run',
        '--rm',
        '-v',
        getcwd() . ':/project:ro',
        '-w',
        '/project',
        'alpine:3.22',
        'sh',
        '-c',
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1'
            . ' && xmlsec1 --decrypt --lax-key-search --privkey-pem '
            . SAML_SP_DIRECTORY
            . '/sp.pem --output /tmp/decrypted.xml '
            . escapeshellarg($file)
            . ' && xmllint --xpath \'/*/*[local-name()="EncryptedAssertion"]/*[local-name()="Assertion"]\' /tmp/decrypted.xml',
    ]);
    $name = basename($file, '.xml') . '.decrypted-assertion.xml';
    file_put_contents(SAML_SP_CAPTURED . '/' . $name, $assertion);
    demo_expect(
        str_contains($assertion, ':Assertion') && str_contains($assertion, 'Signature'),
        sprintf('xmlsec1 decrypts %s into a signed assertion, %s', basename($file), $name),
    );
}

/**
 * Single Logout started by the service provider (issue #734, spec/saml.md section 6.5), on a journey signed in: the
 * browser asks SimpleSAMLphp to sign it out, carries the LogoutRequest it is given to the single logout service of the
 * provider, and the LogoutResponse the provider answers with back to the single logout service of SimpleSAMLphp, which
 * verifies its signature under the metadata of the provider (validate.logout, docker/saml-sp/config/authsources.php).
 * Then what the provider kept of it: the same browser asking SimpleSAMLphp to sign it in again is sent to the login of
 * the provider, its session having ended (S-25); and the same LogoutRequest presented again is refused, with the page
 * of a refusal and no answer (S-23, issue #708).
 *
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
    // no newline: the oracle of 9b reads the file whole, and one would end the Signature parameter
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
 * Every LogoutRequest SimpleSAMLphp sent, by OpenSSL and Python, which verify its detached signature under the
 * certificate of the service provider and inflate its message, as for the AuthnRequest of the redirect.
 *
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
    );
}

/**
 * Single Logout started by the provider (issue #735, spec/saml.md S-29 to S-34), on a journey signed in at SimpleSAMLphp:
 * the browser signs out at the end session endpoint of the provider, which asks it to confirm, no client having named
 * the session; the confirmed logout ends the session of the provider and sends the browser to the single logout
 * service of SimpleSAMLphp with a signed LogoutRequest, captured; SimpleSAMLphp verifies it under the metadata of the
 * provider (validate.logout), ends its own session and answers with a LogoutResponse, captured, which the browser
 * carries back to the single logout service of the provider; the chain ends there, on the page that says the browser
 * is signed out, nobody having named where to go back to (S-34). Then what each kept of it: SimpleSAMLphp holds no
 * session any more, the browser asking it to sign in again is sent to the login of the provider, whose session has
 * ended (S-29), and the same LogoutResponse presented again is refused, with the page of a refusal (S-33).
 *
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, response?: string} $journey
 * @return array{binding: string, url?: string} the binding SimpleSAMLphp answered over, and the URL of its answer when
 *                                              it redirected
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
    // no newline: the oracle of 9b reads the file whole, and one would end the Signature parameter
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
        $carried = ['POST', $form['action'], $form['fields']];
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
 * The part of SimpleSAMLphp in the session of the provider, which the provider records from the queue of its events
 * (spec/saml.md S-26) and which its logout reads to tell it (S-30): the walk signs out within a second of the sign-on,
 * faster than a worker may have written the row, so it waits for the row, by the session index SimpleSAMLphp holds, up to
 * thirty seconds, and says how long it waited. A row that never comes is a failure of the walk, named as such, and not a
 * chain that would end without telling anybody.
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
 * The two messages of the logout the provider started, each by a judge that is neither the provider nor SimpleSAMLphp:
 * the LogoutRequest of the provider by OpenSSL and Python under a certificate of the metadata of the provider, the one
 * of its active key among them; the LogoutResponse of SimpleSAMLphp by the same oracle under its certificate when it
 * was redirected, by xmlsec1 when it was posted.
 *
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
    );
    if ($answer['binding'] === 'redirect') {
        io()->text('OpenSSL and Python, the signature of the LogoutResponse of SimpleSAMLphp over its query string and the message it carries:');
        in_alpine('apk add -q openssl python3 >/dev/null 2>&1 && sh tests/saml2-bindings/Fixture/oracle/verify-redirect.sh '
        . SAML_SP_DIRECTORY
        . '/sp.crt '
        . SAML_SP_CAPTURED
        . '/sp-logout-response.url');
    }
    io()->text('xmlsec1, every XML signature captured, the Response of this sign-on and a LogoutResponse that was posted among them:');
    saml_sp_xmlsec1();
}

/*
 * The Entra judge (issue #736, spec/saml.md sections 7 and 12): Entra's SAML federation of guests, set up without a
 * domain in the maintainer's test tenant, federating the identity provider of the stack. Entra is configured by hand in
 * its portal, by the maintainer and by nobody else; this task prints what the portal takes, registers the service
 * provider the development configuration declares for it, and reads back, once the sign-in was played, what the provider
 * received from Entra.
 *
 * What was received is read from the profiler of the development stack, which collects every request while
 * APP_PROFILER is 1, its default (apps/op/config/packages/web_profiler.yaml): the raw query string of HTTP-Redirect, the
 * fields and the raw body of HTTP-POST, before anything validated them, a request refused included. Nothing is added to
 * the provider for it, and a deployment, which collects no profile, has nothing of it.
 */

/**
 * The test tenant of the maintainer, Entra ID Free (beffroilaboutlook.onmicrosoft.com).
 */
const SAML_ENTRA_TENANT = '20a6e528-cf9e-4f79-8949-bbd59006eff5';

/**
 * The tenanted issuer of the AuthnRequest Entra sends for a new federation, the trailing slash included, as
 * apps/op/config/packages/beffroi.yaml declares it and apps/op/config/saml/entra-guest-federation-sp.xml names it.
 */
const SAML_ENTRA_ENTITY_ID = 'https://login.microsoftonline.com/' . SAML_ENTRA_TENANT . '/';

/**
 * Under the ignored var/ of the repository: the metadata of the provider as Entra's portal can parse them, its signing
 * certificate as the portal takes it, and every document received from Entra.
 */
const SAML_ENTRA_DIRECTORY = 'var/saml-entra';

const SAML_ENTRA_RECEIVED = SAML_ENTRA_DIRECTORY . '/received';

/**
 * Run by the PHP of the op container on the profiler storage of its kernel: the requests profiled at the paths given
 * since the instant given, oldest first, as JSON.
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
    description: 'The Entra judge (issue #736): registers the service provider declared for Entra\'s SAML federation of guests, then prints what the portal of Entra takes (Issuer URI, passive authentication endpoint, signing certificate) and the invitation redirect URL carrying the domain_hint; with --received, lists what the provider received from Entra, read from the profiler of the stack, and writes each document to var/saml-entra/received/ for the corpus',
)]
function saml_entra(
    #[AsOption(
        description: 'List what the provider received from Entra at its single sign-on and single logout services, and write each document to var/saml-entra/received/',
    )]
    bool $received = false,
    #[AsOption(description: 'With --received: how far back the profiles are read, in minutes')]
    int $minutes = 180,
    #[AsOption(description: 'The address the guest is invited with, the email of the user of the provider who signs in')]
    string $email = DEV_USERNAME . '@op.localhost',
): void {
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
        $file = SAML_ENTRA_DIRECTORY . sprintf('/signing-certificate-%d.txt', $index + 1);
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
    io()->writeln(sprintf('<comment>Invitation redirect URL</comment> (domain_hint, the Issuer URI):%s%s%s', \PHP_EOL, $redirect, \PHP_EOL));
    io()->writeln(sprintf(
        '<comment>The invitation</comment>, POST https://graph.microsoft.com/v1.0/invitations in Graph Explorer, the portal taking no redirect URL; its answer carries the "inviteRedeemUrl" the guest opens:%s%s%s',
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
    io()->success(sprintf('%s is registered; once the sign-in is played, "castor saml-entra --received" lists what Entra sent.', SAML_ENTRA_ENTITY_ID));
}

/**
 * What the provider received from Entra since the minutes given, read from the profiles of the stack: each message
 * written to var/saml-entra/received/, the document decoded and the bytes as they came, and described as it arrived.
 * A message posted again by the provider from its own origin (S-28) is the one Entra posted, and is written once.
 */
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
    $written = [];
    foreach ($profiled as $request) {
        $message = saml_entra_message($request);
        if ($message === null || ! saml_entra_is_entra($message['issuer'])) {
            continue;
        }
        $digest = hash('sha256', $message['document']);
        $profile = sprintf('%s/_profiler/%s', $issuer, $request['token']);
        if (isset($written[$digest])) {
            io()->text(sprintf(
                ' the same %s, posted again from the origin of the provider (S-28), answered %d: %s',
                $message['root'],
                $request['status'],
                $profile,
            ));
            continue;
        }
        $base = sprintf('%s/%s-%s-%s', SAML_ENTRA_RECEIVED, date('Ymd\THis', $request['time']), $message['binding'], $message['root']);
        file_put_contents($base . '.xml', $message['document']);
        file_put_contents($base . '.raw.txt', $message['raw']);
        $written[$digest] = $base;
        io()->section(sprintf('%s, %s over %s, answered %d', date('c', $request['time']), $message['root'], $message['binding'], $request['status']));
        io()->listing([
            sprintf(
                'Issuer: %s%s',
                $message['issuer'],
                $message['issuer'] === SAML_ENTRA_ENTITY_ID ? ', the entity ID declared' : ', NOT the entity ID declared (' . SAML_ENTRA_ENTITY_ID . ')',
            ),
            sprintf('Signed: %s', $message['signed'] ? 'yes' : 'no'),
            sprintf('From another site: %s', $request['secFetchSite'] ?? 'not said'),
            ...array_map(
                static fn (string $name, string $value): string => sprintf('%s: %s', $name, $value),
                array_keys($message['facts']),
                array_values($message['facts']),
            ),
            sprintf('Written to %s.xml and %s.raw.txt', $base, $base),
            sprintf('Profile: %s', $profile),
        ]);
        io()->writeln($message['document']);
    }
    if ($written === []) {
        io()->warning(sprintf(
            'Nothing from Entra was profiled in the last %d minutes: --minutes reads further back; a stack started with --conformance collects no profile.',
            $minutes,
        ));

        return;
    }
    io()->success(sprintf('%d document(s) received from Entra written to %s/: they go to the corpus (issue #665).', count($written), SAML_ENTRA_RECEIVED));
}

/**
 * The SAML message a profiled request carried, decoded as its binding encodes it: the raw query string of
 * HTTP-Redirect, its message deflated (SAML Bindings §3.4.4.1), or the field of HTTP-POST (§3.5.4); null when it
 * carries none, or one that does not decode to XML.
 *
 * @param array{method: string, query: string, fields: array<string, mixed>, body: string} $request
 * @return array{binding: string, raw: string, document: string, root: string, issuer: string, signed: bool, facts: array<string, string>}|null
 */
function saml_entra_message(array $request): ?array
{
    if ($request['method'] === 'GET') {
        parse_str($request['query'], $parameters);
        $binding = 'redirect';
        $raw = $request['query'];
    } else {
        $parameters = $request['fields'];
        $binding = 'post';
        $raw = $request['body'];
    }
    $encoded = $parameters['SAMLRequest'] ?? $parameters['SAMLResponse'] ?? null;
    if (! is_string($encoded)) {
        return null;
    }
    $bytes = base64_decode($encoded, true);
    $document = $bytes === false ? false : ($binding === 'redirect' ? @gzinflate($bytes) : $bytes);
    $dom = new DOMDocument();
    if (! is_string($document) || ! @$dom->loadXML($document, \LIBXML_NONET) || ! $dom->documentElement instanceof DOMElement) {
        return null;
    }
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $root = $dom->documentElement;
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
 * Whether an issuer is one of Entra's: the tenanted entity ID of a new federation, any other tenant of the same host,
 * or the global entity ID of the federations made before (spec/saml.md section 7).
 */
function saml_entra_is_entra(string $issuer): bool
{
    return str_starts_with($issuer, 'https://login.microsoftonline.com/') || $issuer === 'urn:federation:MicrosoftOnline';
}
