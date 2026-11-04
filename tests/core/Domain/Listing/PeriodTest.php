<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Listing;

use Beffroi\Core\Domain\Listing\Period;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.2
 */
final class PeriodTest extends TestCase
{
    #[Test]
    public function thePeriodIsTheWholeOfBothDays(): void
    {
        // When
        $period = Period::ofDays(new DateTimeImmutable('2026-10-01 11:30:00'), new DateTimeImmutable('2026-10-03 08:15:00'));

        // Then
        static::assertNotNull($period);
        static::assertSame('2026-10-01 00:00:00.000000', $period->from?->format('Y-m-d H:i:s.u'));
        static::assertSame('2026-10-03 23:59:59.999999', $period->to?->format('Y-m-d H:i:s.u'));
    }

    #[Test]
    public function anEndNobodyNamedIsOpen(): void
    {
        // When
        $period = Period::ofDays(new DateTimeImmutable('2026-10-01 11:30:00'), null);

        // Then
        static::assertNotNull($period);
        static::assertNull($period->to);
    }

    #[Test]
    public function aPeriodThatNamesNeitherEndIsNoPeriodAtAll(): void
    {
        // When / Then
        static::assertNull(Period::ofDays(null, null));
    }

    #[Test]
    public function aPeriodCannotEndBeforeItStarts(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A period from 2026-10-03 00:00:00 to 2026-10-01 23:59:59 ends before it starts.');

        // When
        Period::ofDays(new DateTimeImmutable('2026-10-03 08:15:00'), new DateTimeImmutable('2026-10-01 11:30:00'));
    }

    #[Test]
    public function oneDayIsThatDayWhole(): void
    {
        // When
        $period = Period::ofDays(new DateTimeImmutable('2026-10-01 23:00:00'), new DateTimeImmutable('2026-10-01 01:00:00'));

        // Then
        static::assertNotNull($period);
        static::assertSame('2026-10-01 00:00:00.000000', $period->from?->format('Y-m-d H:i:s.u'));
        static::assertSame('2026-10-01 23:59:59.999999', $period->to?->format('Y-m-d H:i:s.u'));
    }

    #[Test]
    #[DataProvider('provideMomentsAndWhatHoldsThem')]
    public function itSaysWhetherItHoldsAMoment(?string $from, ?string $to, string $moment, bool $held): void
    {
        // Given
        $period = Period::ofDays(
            $from === null ? null : new DateTimeImmutable($from),
            $to === null ? null : new DateTimeImmutable($to),
        );
        static::assertNotNull($period);

        // When / Then
        static::assertSame($held, $period->holds(new DateTimeImmutable($moment)));
    }

    /**
     * @return iterable<string, array{string|null, string|null, string, bool}>
     */
    public static function provideMomentsAndWhatHoldsThem(): iterable
    {
        yield 'the first second of the first day' => ['2026-09-15', '2026-09-16', '2026-09-15 00:00:00', true];
        yield 'the last second of the last day' => ['2026-09-15', '2026-09-16', '2026-09-16 23:59:59', true];
        yield 'the day before the first' => ['2026-09-15', '2026-09-16', '2026-09-14 23:59:59', false];
        yield 'the day after the last' => ['2026-09-15', '2026-09-16', '2026-09-17 00:00:00', false];
        yield 'since a day, long after it' => ['2026-09-15', null, '2027-01-01 12:00:00', true];
        yield 'since a day, before it' => ['2026-09-15', null, '2026-09-14 12:00:00', false];
        yield 'until a day, long before it' => [null, '2026-09-15', '2020-01-01 12:00:00', true];
        yield 'until a day, after it' => [null, '2026-09-15', '2026-09-16 00:00:00', false];
    }
}
