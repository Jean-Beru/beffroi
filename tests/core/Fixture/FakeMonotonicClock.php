<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Port\MonotonicClockInterface;

/**
 * Moves only when it is told to, or when something waits on it.
 */
final class FakeMonotonicClock implements MonotonicClockInterface
{
    /**
     * @var list<int>
     */
    public private(set) array $waited = [];

    private int $now = 0;

    public function now(): int
    {
        return $this->now;
    }

    public function waitFor(int $nanoseconds): void
    {
        $this->waited[] = $nanoseconds;
        $this->now += $nanoseconds;
    }

    public function advance(int $nanoseconds): void
    {
        $this->now += $nanoseconds;
    }
}
