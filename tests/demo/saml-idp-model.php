<?php

declare(strict_types=1);

/*
 * Model half of "castor saml-idp": SimpleSAMLphp's metadata read back by the model (spec/model.md section 6.5, M-2).
 */

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../vendor/autoload.php';

const SAML_IDP_MODEL_ENTITY_ID = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

const SAML_IDP_MODEL_SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

/**
 * @throws RuntimeException
 */
function saml_idp_model_file(string $path): string
{
    $contents = file_get_contents($path);
    if ($contents === false) {
        throw new RuntimeException(sprintf('%s cannot be read.', $path));
    }

    return $contents;
}

/**
 * @throws RuntimeException
 */
function saml_idp_model_verified(bool $condition, string $what): void
{
    if (! $condition) {
        throw new RuntimeException('Not verified: ' . $what);
    }
    printf("  ✓ %s\n", $what);
}

$directory = $argv[1] ?? null;
if ($directory === null || ! is_dir($directory)) {
    throw new InvalidArgumentException('usage: php tests/demo/saml-idp-model.php <directory of the identity provider, var/saml-idp>');
}

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
};
$loader = SamlLoader::create();
$reader = new MetadataReader($loader, $clock);
$document = saml_idp_model_file($directory . '/captured/idp-metadata.xml');
$certificate = saml_idp_model_file($directory . '/idp.crt');
$der = base64_decode((string) preg_replace('~-----[^-]+-----|\s+~', '', $certificate), true);

$descriptor = $reader->readTrusted($loader->load($document));
$idp = $descriptor->identityProvider ?? throw new RuntimeException('Not verified: the metadata hold no identity provider');
saml_idp_model_verified($descriptor->serviceProvider === null, 'readTrusted() reads one identity provider and no service provider');
saml_idp_model_verified($descriptor->entityId === SAML_IDP_MODEL_ENTITY_ID, sprintf('named by the URL of its metadata, %s', SAML_IDP_MODEL_ENTITY_ID));
saml_idp_model_verified(
    array_map(
        static fn (Endpoint $endpoint): array => [$endpoint->binding, $endpoint->location, $endpoint->responseLocation],
        $idp->singleSignOnServices,
    ) === [
        [Binding::HttpRedirect, SAML_IDP_MODEL_SINGLE_SIGN_ON, null],
        [Binding::HttpPost,     SAML_IDP_MODEL_SINGLE_SIGN_ON, null],
    ],
    sprintf('its single sign-on service on HTTP-Redirect and on HTTP-POST, %s', SAML_IDP_MODEL_SINGLE_SIGN_ON),
);
saml_idp_model_verified($idp->nameIdFormats === [NameIdFormat::Persistent], 'the persistent NameID format, and no other');
saml_idp_model_verified(
    is_string($der) && array_map(static fn (string $base64): string|false => base64_decode($base64, true), $idp->signingCertificates) === [$der],
    'one signing certificate, the one drawn for it',
);

$signed = $reader->readSigned($loader->load($document), new VerificationKeys([VerificationKey::fromCertificatePem($certificate)]));
saml_idp_model_verified(
    serialize($signed) === serialize($descriptor),
    'readSigned() verifies their signature under that certificate, pinned, and reads the same identity provider',
);
