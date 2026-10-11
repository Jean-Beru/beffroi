<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Listing;

use Beffroi\Core\Domain\Listing\RetentionWindow;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * How long a store keeps what it holds, and the moment before which it keeps nothing: the one place a
 * number of days becomes a date, whatever store reads it (issues #454, #482, #590).
 */
final class RetentionWindowTest extends TestCase
{
    /**
     * Six months, the default of the deployment, counted back from the instant the step runs on.
     */
    #[Test]
    public function theWindowReachesBackTheDaysItKeeps(): void
    {
        // Given
        $window = new RetentionWindow(180);

        // When
        $since = $window->keptSince(new DateTimeImmutable('2026-10-11 09:30:00'));

        // Then
        static::assertSame('2026-04-14 09:30:00', $since->format('Y-m-d H:i:s'));
    }

    /**
     * The instant is the one given, so what a reading says the journal still covers and what the step
     * forgets are the same moment and not two readings of a clock.
     */
    #[Test]
    public function theMomentIsCountedFromTheInstantGiven(): void
    {
        // Given
        $window = new RetentionWindow(1);

        // When / Then
        static::assertSame(
            '2026-10-10 00:00:00',
            $window->keptSince(new DateTimeImmutable('2026-10-11 00:00:00'))->format('Y-m-d H:i:s'),
        );
    }

    /**
     * Nought days is a value somebody typed, never a duration a deployment means: a store that forgets
     * everything it is handed is refused where the window is built.
     */
    #[Test]
    #[DataProvider('provideDaysThatKeepNothing')]
    public function aWindowKeepsADayOrMore(int $days): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('A retention window keeps a day or more, "%d" given.', $days));

        // When
        new RetentionWindow($days);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideDaysThatKeepNothing(): iterable
    {
        yield 'nothing kept' => [0];
        yield 'a day in the future' => [-1];
    }
}
