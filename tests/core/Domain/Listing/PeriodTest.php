<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Listing;

use Beffroi\Core\Domain\Listing\Period;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The stretch of time a table of the account is read over (architecture §5.2): two days, either of them
 * alone, or none at all.
 */
final class PeriodTest extends TestCase
{
    /**
     * The ends are days and what they mean is the whole of both: a reader who asks for today means today
     * until midnight, not today until the instant they asked.
     */
    #[Test]
    public function thePeriodIsTheWholeOfBothDays(): void
    {
        // When
        $period = Period::ofDays(new DateTimeImmutable('2026-10-01 11:30:00'), new DateTimeImmutable('2026-10-03 08:15:00'));

        // Then
        static::assertSame('2026-10-01 00:00:00.000000', $period?->from?->format('Y-m-d H:i:s.u'));
        static::assertSame('2026-10-03 23:59:59.999999', $period?->to?->format('Y-m-d H:i:s.u'));
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

    /**
     * A table that answered nothing to a question nobody can have meant would be a page somebody reloads.
     */
    #[Test]
    public function aPeriodCannotEndBeforeItStarts(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A period from 2026-10-03 00:00:00 to 2026-10-01 23:59:59 ends before it starts.');

        // When
        Period::ofDays(new DateTimeImmutable('2026-10-03 08:15:00'), new DateTimeImmutable('2026-10-01 11:30:00'));
    }

    /**
     * One day is a period of that day: from its first second to its last, and not an empty stretch.
     */
    #[Test]
    public function oneDayIsThatDayWhole(): void
    {
        // When
        $period = Period::ofDays(new DateTimeImmutable('2026-10-01 23:00:00'), new DateTimeImmutable('2026-10-01 01:00:00'));

        // Then
        static::assertSame('2026-10-01 00:00:00.000000', $period?->from?->format('Y-m-d H:i:s.u'));
        static::assertSame('2026-10-01 23:59:59.999999', $period?->to?->format('Y-m-d H:i:s.u'));
    }
}
