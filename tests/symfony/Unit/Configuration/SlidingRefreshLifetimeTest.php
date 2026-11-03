<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\SlidingRefreshLifetime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Architecture §4.6: no rotation carries a refresh token past the absolute lifetime of its family, so the
 * sliding lifetime it is renewed for is no longer than that one, checked again when the container builds
 * the issuer of the refresh tokens (issue #911).
 */
final class SlidingRefreshLifetimeTest extends TestCase
{
    #[Test]
    #[DataProvider('provideSlidingLifetimesWithinTheAbsoluteOne')]
    public function aSlidingLifetimeWithinTheAbsoluteOneIsTheLifetimeATokenIsRenewedFor(int $sliding): void
    {
        // When
        $lifetime = SlidingRefreshLifetime::interval($sliding, 7_776_000);

        // Then
        static::assertSame($sliding, $lifetime->s);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideSlidingLifetimesWithinTheAbsoluteOne(): iterable
    {
        yield 'shorter' => [2_592_000];
        yield 'as long' => [7_776_000];
    }

    /**
     * Issue #913: a refresh token renewed for no time is expired when it is issued.
     */
    #[Test]
    public function aSlidingLifetimeOfNoTimeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "refresh_token_ttl" is a number of seconds of at least 1, 0 given.');

        // When
        SlidingRefreshLifetime::interval(0, 7_776_000);
    }

    #[Test]
    public function aSlidingLifetimeBeyondTheAbsoluteOneIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).');

        // When
        SlidingRefreshLifetime::interval(7_776_001, 7_776_000);
    }
}
