<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use DateTimeImmutable;
use function file_get_contents;
use function preg_replace;
use function sprintf;
use function str_replace;

/**
 * The metadata documents of a service provider the tests of spec/saml.md section 6.2 read: the one a SimpleSAMLphp
 * 2.5.3.1 service provider published on 30 September 2026 (tests/saml2-model/Fixture/real/), as it is or with one
 * change a test names, a document the model's writer signs with the test key of a service provider, and the document
 * an administrator writes by hand for Entra's SAML federation of guests, which publishes none (spec/saml.md S-9).
 */
final readonly class ServiceProviderDocuments
{
    /**
     * The entity ID of the SimpleSAMLphp service provider.
     */
    public const string SIMPLESAMLPHP = 'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp';

    /**
     * The entity ID of the document the model's writer signs.
     */
    public const string SIGNED = 'https://sp.example.org/saml';

    /**
     * The entity ID of Entra's SAML federation of guests.
     */
    public const string ENTRA = 'urn:federation:MicrosoftOnline';

    /**
     * Where Entra's SAML federation of guests receives the assertion.
     */
    public const string ENTRA_ASSERTION_CONSUMER = 'https://login.microsoftonline.com/login.srf';

    public static function path(): string
    {
        return __DIR__ . '/../../saml2-model/Fixture/real/simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml';
    }

    public static function simpleSamlPhp(): string
    {
        return (string) file_get_contents(self::path());
    }

    /**
     * The SimpleSAMLphp document with a validUntil on its md:EntityDescriptor, which readTrusted() reads without a
     * signature to break.
     */
    public static function simpleSamlPhpValidUntil(string $validUntil): string
    {
        return str_replace(
            sprintf('entityID="%s"', self::SIMPLESAMLPHP),
            sprintf('entityID="%s" validUntil="%s"', self::SIMPLESAMLPHP, $validUntil),
            self::simpleSamlPhp(),
        );
    }

    /**
     * The SimpleSAMLphp document without its md:KeyDescriptor for encryption, its signing key left.
     */
    public static function simpleSamlPhpWithoutEncryptionKey(?string $validUntil = null): string
    {
        $document = $validUntil === null ? self::simpleSamlPhp() : self::simpleSamlPhpValidUntil($validUntil);

        return (string) preg_replace('~\s*<md:KeyDescriptor use="encryption">.*?</md:KeyDescriptor>~s', '', $document);
    }

    /**
     * The SimpleSAMLphp document without its md:KeyDescriptor for signing, its encryption key left and its
     * AuthnRequestsSigned="true" with it.
     */
    public static function simpleSamlPhpWithoutSigningKey(): string
    {
        return (string) preg_replace('~\s*<md:KeyDescriptor use="signing">.*?</md:KeyDescriptor>~s', '', self::simpleSamlPhp());
    }

    /**
     * The SimpleSAMLphp document whose certificates are the given base64, which the model reads with its whitespace
     * removed and checks by building its key.
     */
    public static function simpleSamlPhpWithCertificate(string $base64): string
    {
        return (string) preg_replace('~(<ds:X509Certificate>)[^<]+(</ds:X509Certificate>)~', '${1}' . $base64 . '${2}', self::simpleSamlPhp());
    }

    /**
     * The metadata of the service provider of single sign-on under test (spec/saml.md section 6.4), written once by
     * the model's writer: the entity SIGNED, its assertion consumer service on HTTP-POST at SIGNED/acs, the test key of
     * a service provider of saml2-model for signing, AuthnRequestsSigned.
     */
    public static function exampleOrg(): string
    {
        return (string) file_get_contents(__DIR__ . '/metadata/sp-example-org-metadata.xml');
    }

    /**
     * The metadata of Entra's SAML federation of guests as an administrator writes them: no key, no
     * AuthnRequestsSigned, its assertion consumer service on HTTP-POST.
     */
    public static function entra(): string
    {
        return (string) file_get_contents(__DIR__ . '/metadata/entra-guest-federation-sp.xml');
    }

    /**
     * The Entra document saying AuthnRequestsSigned="true", which contradicts a declaration that says it does not sign.
     */
    public static function entraSigningItsRequests(): string
    {
        return str_replace(
            'protocolSupportEnumeration=',
            'AuthnRequestsSigned="true" protocolSupportEnumeration=',
            self::entra(),
        );
    }

    /**
     * A document of the identity provider of SimpleSAMLphp, which holds no service provider role.
     */
    public static function identityProvider(): string
    {
        return (string) file_get_contents(__DIR__ . '/../../saml2-model/Fixture/real/simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml');
    }

    /**
     * A service provider document signed by a test key of saml2-model, its validUntil given.
     *
     * @param 'idp'|'sp' $key
     */
    public static function signed(?DateTimeImmutable $validUntil, string $key = 'sp'): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(self::SIGNED, $validUntil, serviceProvider: new ServiceProvider(
                self::SIGNED,
                [MetadataFixtures::certificate('sp')],
                [MetadataFixtures::certificate('sp')],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::SIGNED . '/acs', 0)]),
            )),
            new Signing(MetadataFixtures::signingKey($key)),
        ));
    }

    /**
     * The certificate of a test key of saml2-model, as a declaration pins it.
     *
     * @param 'idp'|'sp' $key
     */
    public static function signer(string $key = 'sp'): Certificate
    {
        return new Certificate(MetadataFixtures::certificate($key));
    }
}
