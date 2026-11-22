<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-38
 */
final class ServiceProviderEndpointsTest extends TestCase
{
    /**
     * S-38
     */
    #[Test]
    public function theEntityIdOfTheIdentityProviderIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of the service provider of the tenant, "https://id.acme.example/saml/metadata", is the one of its identity provider: each role is an entity of its own (spec/saml.md S-38).');

        // When
        ServiceProviderEndpoints::assertOwnEntityId('https://id.acme.example/saml/metadata', 'https://id.acme.example/saml/metadata');
    }

    /**
     * S-38, M-8
     */
    #[Test]
    public function anotherEntityIdIsTheServiceProvidersOwn(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        ServiceProviderEndpoints::assertOwnEntityId('https://id.acme.example/saml/metadata/', 'https://id.acme.example/saml/metadata');
    }
}
