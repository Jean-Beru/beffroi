<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
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
 * spec/saml.md section 6.10
 */
final readonly class IdentityProviderDocuments
{
    public const string SIMPLESAMLPHP = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

    public const string SIGNED = 'https://idp.example.org/saml';

    /**
     * spec/saml.md S-43
     */
    public static function path(): string
    {
        return __DIR__ . '/metadata/simplesamlphp-2.5.3.1-idp-metadata-https.xml';
    }

    public static function signedPath(): string
    {
        return __DIR__ . '/metadata/signed-idp-metadata.xml';
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

    public static function simpleSamlPhpWithoutSigningKey(): string
    {
        return (string) preg_replace('~\s*<md:KeyDescriptor use="signing">.*?</md:KeyDescriptor>~s', '', self::simpleSamlPhp());
    }

    public static function simpleSamlPhpSigningOnAt(string $location): string
    {
        return str_replace(
            'Location="https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService"',
            sprintf('Location="%s"', $location),
            self::simpleSamlPhp(),
        );
    }

    public static function simpleSamlPhpSigningOnOverPost(): string
    {
        return str_replace(
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService"',
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService"',
            self::simpleSamlPhp(),
        );
    }

    /**
     * @param list<Endpoint> $singleSignOnServices
     */
    public static function signingOnAt(array $singleSignOnServices): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(self::SIGNED, null, identityProvider: new IdentityProvider(
                self::SIGNED,
                [MetadataFixtures::certificate('idp')],
                [],
                $singleSignOnServices,
            )),
            null,
        ));
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function signed(?DateTimeImmutable $validUntil, string $key = 'idp'): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(self::SIGNED, $validUntil, identityProvider: new IdentityProvider(
                self::SIGNED,
                [MetadataFixtures::certificate('idp')],
                [],
                [new Endpoint(Binding::HttpRedirect, self::SIGNED . '/sso')],
            )),
            new Signing(MetadataFixtures::signingKey($key)),
        ));
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function signer(string $key = 'idp'): Certificate
    {
        return new Certificate(MetadataFixtures::certificate($key));
    }
}
