<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Listing;

use Beffroi\Core\Domain\Listing\RetentionWindow;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RetentionWindowTest extends TestCase
{
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
