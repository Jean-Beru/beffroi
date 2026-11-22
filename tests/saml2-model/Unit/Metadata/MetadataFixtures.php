<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use function file_get_contents;
use function preg_replace;

/**
 * Section 9.1, M-14
 */
final class MetadataFixtures
{
    /**
     * @param 'idp'|'sp'|'idp-b'|'rsa-1024' $key
     */
    public static function certificate(string $key): string
    {
        return (string) preg_replace('~-----[A-Z ]+-----|\s+~', '', self::certificatePem($key));
    }

    /**
     * @param 'idp'|'sp'|'idp-b'|'rsa-1024' $key
     */
    public static function certificatePem(string $key): string
    {
        return self::bytes(match ($key) {
            'idp' => 'keys/idp-signing-certificate.pem',
            'idp-b' => 'keys/idp-b-signing-certificate.pem',
            'sp' => 'keys/sp-signing-certificate.pem',
            'rsa-1024' => 'hostile/metadata-rsa-1024-certificate-refused.pem',
        });
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function signingKey(string $key): PrivateKey
    {
        return PrivateKey::fromPem(self::bytes('keys/' . $key . '-signing-key.pem'));
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function verificationKeys(string $key): VerificationKeys
    {
        return new VerificationKeys([VerificationKey::fromCertificatePem(self::certificatePem($key))]);
    }

    public static function bytes(string $path): string
    {
        return (string) file_get_contents(__DIR__ . '/../../Fixture/' . $path);
    }

    /**
     * M-14
     */
    public static function load(string $path): Document
    {
        return SamlLoader::create()->load(self::bytes($path));
    }
}
