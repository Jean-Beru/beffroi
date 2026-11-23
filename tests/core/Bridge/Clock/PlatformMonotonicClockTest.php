<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Clock;

use Beffroi\Core\Bridge\Clock\PlatformMonotonicClock;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PlatformMonotonicClockTest extends TestCase
{
    #[Test]
    public function itNeverGoesBack(): void
    {
        // Given
        $clock = new PlatformMonotonicClock();
        $before = $clock->now();

        // When
        $after = $clock->now();

        // Then
        static::assertGreaterThanOrEqual($before, $after);
    }
}
