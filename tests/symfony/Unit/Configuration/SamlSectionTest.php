<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use Beffroi\Bundle\Configuration\SamlSection;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Decision 0030, issue #912: a list of SAML declarations the environment carries is a value only when the container
 * runs, so what the compilation checks of a written one, the role the tenant has to play and the entity IDs of the
 * tenant itself, the factory of the declarations checks then.
 */
final class SamlSectionTest extends TestCase
{
    /**
     * Spec/saml.md section 5.2: the service providers of a tenant are served by its identity provider.
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
     * Spec/saml.md S-42: a tenant is never upstream of itself, and an identity provider declared under the URL of the
     * metadata of its identity provider is refused when the container runs, the issuer being a value then.
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
}
