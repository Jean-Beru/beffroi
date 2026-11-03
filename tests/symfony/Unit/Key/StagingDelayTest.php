<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Key;

use DateTimeImmutable;
use App\Key\StagingDelay;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

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

    /**
     * Issue #911: an environment variable nobody set is an empty string, which is no delay configured.
     */
    #[Test]
    public function anEmptyDelayDerivesFromTheJwksMaxAge(): void
    {
        // When / Then
        static::assertSame(180, StagingDelay::seconds('', 120));
    }

    #[Test]
    public function theDigitsAnEnvironmentVariableCarriesAreTheDelay(): void
    {
        // When / Then
        static::assertSame(604800, StagingDelay::seconds('604800', 120));
    }

    #[Test]
    #[DataProvider('provideDelaysThatAreNoNumberOfSeconds')]
    public function aDelayThatIsNoNumberOfSecondsIsRefused(int|string $configured): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs(\sprintf(
            'The "beffroi" configuration key "staging_delay" is a number of seconds, or nothing for the max-age of the JWK Set plus 60, "%s" given.',
            $configured,
        ));

        // When
        StagingDelay::seconds($configured, 120);
    }

    /**
     * @return iterable<string, array{int|string}>
     */
    public static function provideDelaysThatAreNoNumberOfSeconds(): iterable
    {
        yield 'a negative number' => [-1];
        yield 'negative digits' => ['-1'];
        yield 'a word' => ['soon'];
        yield 'a fraction' => ['1.5'];
        yield 'digits and a line feed' => ["30\n"];
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
