<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009: a client of a tenant as whoever runs the deployment sees it, and the one thing that
 * decides what may be done to it here.
 */
final class InventoriedClientTest extends TestCase
{
    /**
     * A client this provider registered can be taken back here, because taking the row away is what
     * takes it away.
     */
    #[Test]
    public function aClientThisProviderRegisteredWasRegisteredHere(): void
    {
        // Given
        $client = new InventoriedClient('registration', 'drawn', 'A client that registered itself', new DateTimeImmutable('2026-09-01T10:00:00+00:00'));

        // When / Then
        static::assertTrue($client->wasRegisteredHere());
    }

    /**
     * A declaration was not registered on a day and has nobody's history behind it: it carries neither
     * date, and nothing of this provider takes it back.
     */
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

    /**
     * The two dates come from one row and say one story: a use recorded before the registration is a row
     * nothing wrote.
     */
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
