<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Random;

use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

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

        // When / Then
        static::assertNotSame($randomness->bytes(8), $randomness->bytes(8));
    }

    #[Test]
    #[DataProvider('provideLengths')]
    public function whatItDrawsOnItsOwnIsOfTheLengthAskedFor(int $length): void
    {
        // When / Then
        static::assertSame($length, strlen(new FixedRandomness()->bytes($length)));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideLengths(): iterable
    {
        yield 'shorter than the counter' => [2];
        yield 'as long as the counter' => [4];
        yield 'longer than the counter' => [32];
    }

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
