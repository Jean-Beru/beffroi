<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/saml.md S-38: the entity ID of the service provider of a tenant, an absolute URI of its own, never the one of
 * its identity provider.
 */
final class ServiceProviderEndpointsTest extends TestCase
{
    private const string METADATA = 'https://id.acme.example/saml/sp/metadata';

    private const string ASSERTION_CONSUMER_SERVICE = 'https://id.acme.example/saml/sp/acs';

    /**
     * S-38, Metadata §2.2.1: an entity ID is an absolute URI of at most 1024 characters, and one of 1024 is one.
     */
    #[Test]
    public function anEntityIdOfTheLongestLengthIsAccepted(): void
    {
        // Given
        $entityId = 'urn:' . str_repeat('a', 1_020);

        // When
        $endpoints = new ServiceProviderEndpoints($entityId, self::METADATA, self::ASSERTION_CONSUMER_SERVICE);

        // Then
        static::assertSame($entityId, $endpoints->entityId);
    }

    /**
     * S-38, M-6: an entity ID that is not an absolute URI of at most 1024 characters with no whitespace is refused
     * where the endpoints are built.
     */
    #[Test]
    #[DataProvider('provideEntityIdsRefused')]
    public function anEntityIdThatIsNotOneIsRefused(string $entityId): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of the service provider of a tenant is an absolute URI of at most 1024 characters with no whitespace (spec/saml.md S-38).');

        // When
        new ServiceProviderEndpoints($entityId, self::METADATA, self::ASSERTION_CONSUMER_SERVICE);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEntityIdsRefused(): iterable
    {
        yield 'empty' => [''];
        yield 'no scheme' => ['sp.acme.example'];
        yield 'whitespace' => ['https://id.acme.example/saml sp'];
        yield 'longer than 1024 characters' => ['urn:' . str_repeat('a', 1_021)];
    }

    /**
     * S-38: the entity ID of the identity provider of the tenant is not the one of its service provider.
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
     * S-38, M-8: the two are compared exactly, so an entity ID that differs from the one of the identity provider by
     * a character is the service provider's own.
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
