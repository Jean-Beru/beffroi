<?php

declare(strict_types=1);

/*
 * The service provider of the stack judged by an upstream identity provider that is not this project's (sub-spike 9d,
 * issue #788): SimpleSAMLphp 2.5.3.1, from the image of the judges of 9b (tests/saml2-bindings/Interop/simplesamlphp),
 * served on https://saml-idp.localhost by the "saml-idp" service of compose.yaml behind the Caddy of op and configured
 * by docker/saml-idp/: two people, alice and bob, a persistent NameID, its responses, assertions and metadata signed by
 * a key drawn here, and the metadata of the service provider of the stack read from the provider.
 *
 * What it serves is judged before anything signs in: its metadata, fetched over https under the root of the certificate
 * of the stack, are verified by xmlsec1, which is not the provider and not SimpleSAMLphp, under the certificate they
 * publish, and read by the model the provider reads an upstream identity provider with (tests/demo/saml-idp-model.php),
 * readTrusted() and then readSigned() under the certificate drawn here. Every document of a run is in
 * var/saml-idp/captured/.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;

const SAML_IDP_URL = 'https://saml-idp.localhost';

/**
 * The entity ID of the identity provider, the URL of its metadata, as docker/saml-idp/metadata/saml20-idp-hosted.php
 * names it.
 */
const SAML_IDP_ENTITY_ID = SAML_IDP_URL . '/simplesaml/module.php/saml/idp/metadata';

/**
 * Under the ignored var/ of the repository, mounted into the saml-idp service: the key and the certificate of the
 * identity provider, the root of the certificate of the stack it verifies the provider with, and every document of a
 * run.
 */
const SAML_IDP_DIRECTORY = 'var/saml-idp';

const SAML_IDP_CAPTURED = SAML_IDP_DIRECTORY . '/captured';

#[AsTask(
    name: 'saml-idp',
    description: 'The service provider of the stack judged by a SimpleSAMLphp 2.5.3.1 identity provider (issue #788): the identity provider is started on https://saml-idp.localhost with a key drawn under var/saml-idp/, and the metadata it serves are verified by xmlsec1 under the certificate they publish and read by the model, readTrusted() and then readSigned() under the certificate drawn; then the URL of its metadata is printed',
)]
function saml_idp(
    #[AsOption(description: 'Stop the identity provider')]
    bool $stop = false,
): void {
    if ($stop) {
        run(['docker', 'compose', '--profile', 'saml-idp', 'rm', '--stop', '--force', 'saml-idp']);

        return;
    }

    io()->title('SimpleSAMLphp 2.5.3.1, an identity provider upstream of the stack');

    io()->section('The identity provider');
    $ca = saml_idp_start();

    io()->section('Its metadata');
    saml_idp_metadata($ca);

    io()->success(sprintf('%s serves SimpleSAMLphp as an identity provider; its metadata: %s', SAML_IDP_URL, SAML_IDP_ENTITY_ID));
}

/**
 * The identity provider up, behind Caddy, with a key and a certificate of its own, drawn here and not committed, as the
 * pair of the service provider of "castor saml-sp" is not: what a development stack generates stays under var/.
 *
 * @return string the root of the certificate of the stack, with which every request of the walk verifies it
 */
function saml_idp_start(): string
{
    foreach ([SAML_IDP_DIRECTORY, SAML_IDP_CAPTURED] as $directory) {
        if (! is_dir($directory) && ! mkdir($directory, 0o777, true) && ! is_dir($directory)) {
            io()->error(sprintf('Cannot create %s.', $directory));
            exit(1);
        }
    }
    foreach (glob(SAML_IDP_CAPTURED . '/*') ?: [] as $file) {
        unlink($file);
    }
    // first, so that a stack that is not up is said before anything starts; read by www-data in the container, a
    // certificate and no secret
    $ca = caddy_ca(getcwd() . '/' . SAML_IDP_DIRECTORY . '/caddy-root.crt');
    chmod($ca, 0o644);
    $drawn = ! is_file(SAML_IDP_DIRECTORY . '/idp.pem') || ! is_file(SAML_IDP_DIRECTORY . '/idp.crt');
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
            '/CN=saml-idp.localhost',
            '-keyout',
            SAML_IDP_DIRECTORY . '/idp.pem',
            '-out',
            SAML_IDP_DIRECTORY . '/idp.crt',
        ], context: context()->withQuiet());
    }
    // Its owner's alone: the container reads it as root and hands www-data a copy of its own (compose.yaml).
    chmod(SAML_IDP_DIRECTORY . '/idp.pem', 0o600);
    // A container that copied the key of an earlier pair holds it until it is created again.
    run(['docker', 'compose', '--profile', 'saml-idp', 'up', '-d', '--wait', '--build', ...($drawn ? ['--force-recreate'] : []), 'saml-idp']);

    $cookies = [];
    for ($attempt = 0; $attempt < 30; ++$attempt) {
        try {
            [$status] = demo_request($cookies, $ca, 'GET', SAML_IDP_ENTITY_ID);
        } catch (HttpClientException) {
            $status = 0;
        }
        if ($status === 200) {
            io()->text(sprintf(' <info>✓</info> %s answers through the Caddy of op', SAML_IDP_ENTITY_ID));

            return $ca;
        }
        sleep(1);
    }
    io()->error(sprintf('%s does not answer: "docker compose --profile saml-idp logs saml-idp" says why.', SAML_IDP_ENTITY_ID));
    exit(1);
}

/**
 * The metadata of the identity provider, over https under the certificate of the stack, captured, then judged by
 * xmlsec1 and by the model.
 */
function saml_idp_metadata(string $ca): void
{
    $cookies = [];
    [$status, , $document, $headers] = demo_request($cookies, $ca, 'GET', SAML_IDP_ENTITY_ID);
    demo_expect(
        $status === 200 && ($headers['content-type'][0] ?? '') === 'application/samlmetadata+xml',
        sprintf(
            '%s serves the metadata of the identity provider, application/samlmetadata+xml, over https under the certificate of the stack',
            SAML_IDP_ENTITY_ID,
        ),
    );
    file_put_contents(SAML_IDP_CAPTURED . '/idp-metadata.xml', $document);

    io()->text('xmlsec1, the signature of the metadata under the certificate they publish:');
    in_alpine(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh '
        . SAML_IDP_CAPTURED
        . ' "idp-metadata.xml"',
        ['tests/saml2-model/Interop/simplesamlphp/xmlsec1-verify.sh', SAML_IDP_CAPTURED],
    );

    io()->text('The model, as the provider reads an upstream identity provider:');
    saml_sp_in_phpqa('tests/demo/saml-idp-model.php', SAML_IDP_DIRECTORY);
}
