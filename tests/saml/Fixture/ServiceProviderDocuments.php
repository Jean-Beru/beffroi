<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
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
 * spec/saml.md S-9, section 6.2
 */
final readonly class ServiceProviderDocuments
{
    public const string SIMPLESAMLPHP = 'https://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp';

    public const string SIGNED = 'https://sp.example.org/saml';

    /**
     * spec/saml.md section 7
     */
    public const string ENTRA = 'https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/';

    public const string ENTRA_ASSERTION_CONSUMER = 'https://login.microsoftonline.com/login.srf';

    /**
     * spec/saml.md S-11
     */
    public static function path(): string
    {
        return __DIR__ . '/metadata/simplesamlphp-2.5.3.1-sp-metadata-https.xml';
    }

    public static function simpleSamlPhp(): string
    {
        return (string) file_get_contents(self::path());
    }

    public static function simpleSamlPhpValidUntil(string $validUntil): string
    {
        return str_replace(
            sprintf('entityID="%s"', self::SIMPLESAMLPHP),
            sprintf('entityID="%s" validUntil="%s"', self::SIMPLESAMLPHP, $validUntil),
            self::simpleSamlPhp(),
        );
    }

    public static function simpleSamlPhpWithoutEncryptionKey(?string $validUntil = null): string
    {
        $document = $validUntil === null ? self::simpleSamlPhp() : self::simpleSamlPhpValidUntil($validUntil);

        return (string) preg_replace('~\s*<md:KeyDescriptor use="encryption">.*?</md:KeyDescriptor>~s', '', $document);
    }

    public static function simpleSamlPhpWithoutSigningKey(): string
    {
        return (string) preg_replace('~\s*<md:KeyDescriptor use="signing">.*?</md:KeyDescriptor>~s', '', self::simpleSamlPhp());
    }

    public static function simpleSamlPhpWithCertificate(string $base64): string
    {
        return (string) preg_replace('~(<ds:X509Certificate>)[^<]+(</ds:X509Certificate>)~', '${1}' . $base64 . '${2}', self::simpleSamlPhp());
    }

    /**
     * spec/saml.md section 6.4
     */
    public static function exampleOrg(): string
    {
        return (string) file_get_contents(__DIR__ . '/metadata/sp-example-org-metadata.xml');
    }

    /**
     * SAML Metadata §2.4.2, §2.4.4
     *
     * @param list<array{string, string, ?string}> $services Binding, Location and ResponseLocation
     */
    public static function exampleOrgWithSingleLogout(array $services): string
    {
        $elements = '';
        foreach ($services as [$binding, $location, $responseLocation]) {
            $elements .= sprintf(
                '<md:SingleLogoutService Binding="%s" Location="%s"%s/>',
                $binding,
                $location,
                $responseLocation === null ? '' : sprintf(' ResponseLocation="%s"', $responseLocation),
            );
        }

        return str_replace('<md:AssertionConsumerService ', $elements . '<md:AssertionConsumerService ', self::exampleOrg());
    }

    public static function entra(): string
    {
        return (string) file_get_contents(__DIR__ . '/metadata/entra-guest-federation-sp.xml');
    }

    public static function entraSigningItsRequests(): string
    {
        return str_replace(
            'protocolSupportEnumeration=',
            'AuthnRequestsSigned="true" protocolSupportEnumeration=',
            self::entra(),
        );
    }

    public static function identityProvider(): string
    {
        return (string) file_get_contents(__DIR__ . '/../../saml2-model/Fixture/real/simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml');
    }

    /**
     * spec/saml.md S-27, S-11
     *
     * @param 'idp'|'sp' $key
     * @param list<Endpoint> $singleLogoutServices
     */
    public static function signed(
        ?DateTimeImmutable $validUntil,
        string $key = 'sp',
        array $singleLogoutServices = [],
        string $assertionConsumerService = self::SIGNED . '/acs',
    ): string {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(self::SIGNED, $validUntil, serviceProvider: new ServiceProvider(
                self::SIGNED,
                [MetadataFixtures::certificate('sp')],
                [MetadataFixtures::certificate('sp')],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, $assertionConsumerService, 0)]),
                $singleLogoutServices,
            )),
            new Signing(MetadataFixtures::signingKey($key)),
        ));
    }

    /**
     * spec/saml.md S-30
     *
     * @param 'idp'|'sp' $key
     * @param list<Endpoint> $singleLogoutServices
     */
    public static function of(string $entityId, string $key, array $singleLogoutServices): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor($entityId, null, serviceProvider: new ServiceProvider(
                $entityId,
                [MetadataFixtures::certificate($key)],
                [MetadataFixtures::certificate($key)],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, $entityId . '/acs', 0)]),
                $singleLogoutServices,
            )),
            new Signing(MetadataFixtures::signingKey($key)),
        ));
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function signer(string $key = 'sp'): Certificate
    {
        return new Certificate(MetadataFixtures::certificate($key));
    }
}
