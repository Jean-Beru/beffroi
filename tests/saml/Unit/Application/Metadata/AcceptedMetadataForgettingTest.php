<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\Metadata\AcceptedMetadataForgetting;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-6, section 6.2
 */
final class AcceptedMetadataForgettingTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    private Tenant $tenant;

    private InMemoryAcceptedMetadata $accepted;

    private AcceptedMetadataForgetting $forgetting;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->accepted = new InMemoryAcceptedMetadata();
        $this->forgetting = new AcceptedMetadataForgetting($this->accepted, $this->accepted);
    }

    /**
     * S-6, section 6.2
     */
    #[Test]
    public function theAcceptedDocumentIsForgotten(): void
    {
        // Given
        $this->accepted->save(self::accepted($this->tenant, self::ENTITY_ID));

        // When
        $forgotten = $this->forgetting->forget($this->tenant, self::ENTITY_ID);

        // Then
        static::assertTrue($forgotten);
        static::assertNull($this->accepted->find($this->tenant, self::ENTITY_ID));
    }

    /**
     * Section 6.2
     */
    #[Test]
    public function anEntityIdNothingIsAcceptedForForgetsNothing(): void
    {
        // Given
        $this->accepted->save(self::accepted($this->tenant, self::ENTITY_ID));

        // When
        $forgotten = $this->forgetting->forget($this->tenant, self::ENTITY_ID . '/');

        // Then
        static::assertFalse($forgotten);
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $this->accepted->find($this->tenant, self::ENTITY_ID));
    }

    /**
     * Section 6.2
     */
    #[Test]
    public function theDocumentOfAnotherTenantIsNotForgotten(): void
    {
        // Given
        $other = Fixtures::tenant('other');
        $this->accepted->save(self::accepted($other, self::ENTITY_ID));

        // When
        $forgotten = $this->forgetting->forget($this->tenant, self::ENTITY_ID);

        // Then
        static::assertFalse($forgotten);
        static::assertInstanceOf(AcceptedServiceProviderMetadata::class, $this->accepted->find($other, self::ENTITY_ID));
    }

    private static function accepted(Tenant $tenant, string $entityId): AcceptedMetadata
    {
        return new AcceptedServiceProviderMetadata(
            Uuid::v7(),
            $tenant,
            $entityId,
            '<md:EntityDescriptor/>',
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
            Fixtures::now(),
        );
    }
}
