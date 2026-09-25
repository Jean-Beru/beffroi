<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Random;

use Heidi\Core\Bridge\Random\FixedRandomness;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

/**
 * The randomness a test writes down: what it wrote first, then a sequence that repeats nothing.
 */
final class FixedRandomnessTest extends TestCase
{
    #[Test]
    public function itHandsBackWhatItWasGiven(): void
    {
        // Given
        $randomness = new FixedRandomness([str_repeat("\x01", 4), str_repeat("\x02", 4)]);

        // When / Then
        static::assertSame([str_repeat("\x01", 4), str_repeat("\x02", 4)], [$randomness->bytes(4), $randomness->bytes(4)]);
    }

    #[Test]
    public function itDrawsOnWhenWhatItWasGivenRunsOut(): void
    {
        // Given
        $randomness = new FixedRandomness();

        // When
        $first = $randomness->bytes(8);

        // Then
        static::assertSame(8, strlen($first));
        static::assertNotSame($first, $randomness->bytes(8));
    }

    /**
     * Bytes written for a draw of another length are a mistake in the test, and are said to be.
     */
    #[Test]
    public function bytesOfAnotherLengthAreRefused(): void
    {
        // Given
        $randomness = new FixedRandomness([str_repeat("\x01", 4)]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Draw 1 was written as 4 bytes and is asked for 8.');

        // When
        $randomness->bytes(8);
    }
}
