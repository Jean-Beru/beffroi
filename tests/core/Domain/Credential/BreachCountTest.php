<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\BreachCount;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The three answers a list of compromised passwords has, told apart here rather than at every call site
 * (decision 0006): counted, not counted, and nothing asked.
 */
final class BreachCountTest extends TestCase
{
    #[Test]
    public function aPasswordTheListCountsIsBreached(): void
    {
        // Given
        $count = BreachCount::times(3);

        // Then
        static::assertTrue($count->wasAsked());
        static::assertTrue($count->isBreached());
        static::assertSame(3, $count->times);
    }

    #[Test]
    public function aPasswordTheListDoesNotHoldWasAskedAboutAndIsNotBreached(): void
    {
        // Given
        $count = BreachCount::times(0);

        // Then
        static::assertTrue($count->wasAsked());
        static::assertFalse($count->isBreached());
    }

    /**
     * A deployment that names no list cannot read as one that looked and found nothing.
     */
    #[Test]
    public function nothingAskedIsNeitherOfTheTwo(): void
    {
        // Given
        $count = BreachCount::nothingAsked();

        // Then
        static::assertFalse($count->wasAsked());
        static::assertFalse($count->isBreached());
        static::assertNull($count->times);
    }

    #[Test]
    public function aNegativeCountIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A list counts a password zero times or more.');

        // When
        BreachCount::times(-1);
    }
}
