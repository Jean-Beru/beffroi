<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009
 */
final class InventoriedClientTest extends TestCase
{
    #[Test]
    public function aClientThisProviderRegisteredWasRegisteredHere(): void
    {
        // Given
        $client = new InventoriedClient('registration', 'drawn', 'A client that registered itself', new DateTimeImmutable('2026-09-01T10:00:00+00:00'));

        // When / Then
        static::assertTrue($client->wasRegisteredHere());
    }

    #[Test]
    public function aDeclaredClientCarriesNoDateAndWasNotRegisteredHere(): void
    {
        // Given
        $client = new InventoriedClient('configuration', 'oidc-demo', 'Demo application');

        // When / Then
        static::assertFalse($client->wasRegisteredHere());
    }

    #[Test]
    public function itNamesAClient(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A client of a tenant carries the identifier it is known by (RFC 7591 section 2).');

        // When
        new InventoriedClient('registration', '');
    }

    #[Test]
    public function itIsNotUsedBeforeItIsRegistered(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A client was not used before it was registered.');

        // When
        new InventoriedClient(
            'registration',
            'drawn',
            null,
            new DateTimeImmutable('2026-09-02T10:00:00+00:00'),
            new DateTimeImmutable('2026-09-01T10:00:00+00:00'),
        );
    }
}
