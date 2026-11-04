<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Verifier;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, section 7, SAML Metadata §2.4.4
 */
final class ServiceProviderTest extends TestCase
{
    /**
     * Section 5.3
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // Given
        $assertionConsumers = $this->assertionConsumers();
        $singleLogout = [new Endpoint(Binding::HttpRedirect, 'https://sp.example.com/slo')];

        // When
        $sp = new ServiceProvider(
            'https://sp.example.com',
            [MetadataFixtures::certificate('sp')],
            [MetadataFixtures::certificate('idp')],
            $assertionConsumers,
            $singleLogout,
            [NameIdFormat::EmailAddress],
            true,
            true,
        );

        // Then
        static::assertSame(
            [
                'https://sp.example.com',
                [MetadataFixtures::certificate('sp')],
                [MetadataFixtures::certificate('idp')],
                $assertionConsumers,
                $singleLogout,
                [NameIdFormat::EmailAddress],
                true,
                true,
            ],
            [
                $sp->entityId,
                $sp->signingCertificates,
                $sp->encryptionCertificates,
                $sp->assertionConsumerServices,
                $sp->singleLogoutServices,
                $sp->nameIdFormats,
                $sp->authnRequestsSigned,
                $sp->wantAssertionsSigned,
            ],
        );
    }

    /**
     * Section 6.5 step 7
     */
    #[Test]
    public function itHasNoLogoutServiceNoFormatAndNoFlagByDefault(): void
    {
        // When
        $sp = new ServiceProvider('https://sp.example.com', [], [], $this->assertionConsumers());

        // Then
        static::assertSame(
            [[], [], false, false],
            [$sp->singleLogoutServices, $sp->nameIdFormats, $sp->authnRequestsSigned, $sp->wantAssertionsSigned],
        );
    }

    /**
     * M-17
     */
    #[Test]
    public function itAppliesTheRulesOfARole(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A role holds more than 64 single logout services, the bound of section 7 (M-17).');

        // When
        new ServiceProvider(
            'https://sp.example.com',
            [],
            [],
            $this->assertionConsumers(),
            array_fill(0, 65, new Endpoint(Binding::HttpRedirect, 'https://sp.example.com/slo')),
        );
    }

    /**
     * M-3, section 5.3
     */
    #[Test]
    public function itHasTheKeysOfItsSigningCertificates(): void
    {
        // Given
        $sp = new ServiceProvider(
            'https://sp.example.com',
            [MetadataFixtures::certificate('sp')],
            [],
            $this->assertionConsumers(),
        );
        $signature = MetadataFixtures::signingKey('sp')->sign('signed bytes', SignatureAlgorithm::RsaSha256);

        // When
        $keys = $sp->verificationKeys() ?? static::fail('The role has a signing certificate.');

        // Then
        static::assertSame(
            $keys->keys[0],
            new Verifier(SamlLoader::create())->verifyDetached(
                'signed bytes',
                $signature,
                SignatureAlgorithm::RsaSha256,
                $keys,
            ),
        );
    }

    /**
     * Section 5.3, M-3
     */
    #[Test]
    public function itHasNoKeysWithoutASigningCertificate(): void
    {
        // Given
        $sp = new ServiceProvider(
            'https://sp.example.com',
            [],
            [MetadataFixtures::certificate('sp')],
            $this->assertionConsumers(),
        );

        // When / Then
        static::assertNull($sp->verificationKeys());
    }

    private function assertionConsumers(): IndexedEndpoints
    {
        return new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', 0)]);
    }
}
