<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Key;

use DateTimeImmutable;
use Heidi\Bundle\Key\StagingDelay;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3 and §9: the staging window is at least the JWK Set max-age plus the refetch cooldown
 * of oidc_login, so that a relying party with a warm cache, even one served by a shared HTTP cache, sees
 * the new key when it starts signing.
 */
final class StagingDelayTest extends TestCase
{
    #[Test]
    public function theDelayDerivesFromTheJwksMaxAgeAndTheRefetchCooldown(): void
    {
        // When / Then
        static::assertSame(180, StagingDelay::seconds(null, 120));
    }

    #[Test]
    public function theDefaultsGiveSixMinutes(): void
    {
        // When / Then
        static::assertSame(360, StagingDelay::seconds(null, JwksHandler::DEFAULT_MAX_AGE));
    }

    #[Test]
    public function aConfiguredDelayWins(): void
    {
        // When / Then
        static::assertSame(30, StagingDelay::seconds(30, 120));
    }

    #[Test]
    public function theIntervalIsTheDelayInSeconds(): void
    {
        // Given
        $now = new DateTimeImmutable('2026-09-15T10:00:00+00:00');

        // When
        $interval = StagingDelay::interval(null, 120);

        // Then
        static::assertEquals(new DateTimeImmutable('2026-09-15T10:03:00+00:00'), $now->add($interval));
    }
}
