<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\SamlSection;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Decision 0030
 */
final class SamlSectionTest extends TestCase
{
    /**
     * spec/saml.md section 5.2
     */
    #[Test]
    public function serviceProvidersOfATenantThatIsNoIdentityProviderAreRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Service providers are declared for a tenant that is a SAML identity provider: enable "beffroi.saml.identity_provider", or remove "beffroi.saml.service_providers".');

        // When
        SamlSection::declaredServiceProviders(
            'default',
            ['https://sp.example.org/saml' => ['metadata' => '/srv/saml/sp-example-org-metadata.xml']],
            static::createStub(ServedClaimsInterface::class),
            false,
        );
    }

    /**
     * spec/saml.md S-42
     */
    #[Test]
    public function anUpstreamIdentityProviderNamedAsTheTenantIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "https://op.test/saml/metadata" is declared under the entity ID of the identity provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).');

        // When
        SamlSection::declaredIdentityProviders(
            'default',
            [
                'https://op.test/saml/metadata' => [
                    'metadata' => 'https://op.test/saml/metadata',
                    'domains' => ['acme.example'],
                    'email_attribute' => 'mail',
                ],
            ],
            static::createStub(ProfileClaimsInterface::class),
            true,
            'https://op.test',
            null,
        );
    }

    /**
     * spec/saml.md S-64, Decision 0030
     */
    #[Test]
    public function noUpstreamIdentityProviderHasTheAlgorithmOfAKeyWhileTheServiceProviderIsOff(): void
    {
        // When
        $algorithms = SamlSection::encryptionAlgorithms(
            [
                'https://idp.acme.example/saml' => [
                    'metadata' => 'https://idp.acme.example/saml/metadata',
                    'domains' => ['acme.example'],
                    'email_attribute' => 'mail',
                ],
            ],
            false,
            new RsaKeyBits(),
        );

        // Then
        static::assertSame([], $algorithms->all());
    }
}
