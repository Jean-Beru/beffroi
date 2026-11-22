<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\BreachCount;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0006
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
