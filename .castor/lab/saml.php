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
 * What the next stories attach to, each at the place named, and nothing of it is built before its story:
 *   #734, #735 (Single Logout)  a saml_sp_log_out() beside saml_sp_sign_on_at_the_provider(), played on the journeys
 *                               saml_sp() holds once they are signed in: the SP starts it at
 *                               /simplesaml/module.php/saml/sp/logout/beffroi, the provider starts it for the
 *                               session index the status page shows
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
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
    description: 'The SAML identity provider of the stack judged by SimpleSAMLphp 2.5.3.1 (issue #732): the service provider is started on https://saml-sp.localhost, reads the metadata of the provider and is registered at it by a metadata file and "beffroi:saml:service-provider:refresh"; then single sign-on is played in HTTP-Redirect and in HTTP-POST as a browser plays it, as the development user, and the attributes SimpleSAMLphp received are printed. Every AuthnRequest is verified by xmlsec1 or by OpenSSL and Python (the detached signature of the redirect) and accepted by the model; every Response by xmlsec1. Each journey is a browser of its own, which signs in at the provider',
)]
function saml_sp(
    #[AsOption(description: 'Only start the service provider, read the metadata of the provider and register it: no sign-on')]
    bool $up = false,
    #[AsOption(description: 'Play the HTTP-Redirect binding alone')]
    bool $redirect = false,
    #[AsOption(description: 'Play the HTTP-POST binding alone')]
    bool $post = false,
    #[AsOption(description: 'Play the service provider that demands its assertion encrypted, "beffroi-encrypted" (issue #733): the assertion on the wire checked to be encrypted, then decrypted by xmlsec1 before its signature is verified')]
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
    saml_sp_verify_responses($journeys);

    io()->success(sprintf(
        'SimpleSAMLphp signed %s in at %s over %s%s, and every document that crossed was verified.',
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
 * @param array{binding: string, source?: string, cookies: array<string, array<string, string>>, request: array{method: string, url: string, fields: array<string, string>}, ssoUrl: string} $journey
 * @return array{binding: string, cookies: array<string, array<string, string>>, response?: string}
 */
function saml_sp_sign_on_at_the_provider(array $journey, string $issuer, string $password, string $ca): array
{
    $source = $journey['source'] ?? 'beffroi';
    $cookies = $journey['cookies'];
    $request = $journey['request'];
    $binding = SAML_SP_BINDINGS[$journey['binding']];

    [$status, $location, $page] = demo_request($cookies, $ca, $request['method'], $request['url'], $request['fields']);
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
    $name = sprintf('response-%s.xml', $journey['binding']);
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
        'cookies' => $cookies,
        'response' => $name,
    ];
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
 * and no assertion in clear, its content under aes256-gcm and its key under rsa-oaep-mgf1p, and nothing of it names
 * CBC.
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
        (int) $xpath->evaluate('count(/samlp:Response/saml:EncryptedAssertion)') === 1
        && (int) $xpath->evaluate('count(//saml:Assertion)') === 0,
        'its assertion is encrypted: one saml:EncryptedAssertion, no saml:Assertion in clear',
    );
    demo_expect(
        (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)') === SAML_SP_ENCRYPTION['content']
        && (string) $xpath->evaluate('string(/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)') === SAML_SP_ENCRYPTION['key'],
        sprintf('under %s, its key under %s', SAML_SP_ENCRYPTION['content'], SAML_SP_ENCRYPTION['key']),
    );
    demo_expect(stripos($response, 'cbc') === false, 'nothing of it names CBC');
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
            . ' && xmlsec1 --decrypt --lax-key-search --privkey-pem ' . SAML_SP_DIRECTORY . '/sp.pem --output /tmp/decrypted.xml ' . escapeshellarg($file)
            . ' && xmllint --xpath \'/*/*[local-name()="EncryptedAssertion"]/*[local-name()="Assertion"]\' /tmp/decrypted.xml',
    ]);
    $name = basename($file, '.xml') . '.decrypted-assertion.xml';
    file_put_contents(SAML_SP_CAPTURED . '/' . $name, $assertion);
    demo_expect(str_contains($assertion, ':Assertion') && str_contains($assertion, 'Signature'), sprintf('xmlsec1 decrypts %s into a signed assertion, %s', basename($file), $name));
}
