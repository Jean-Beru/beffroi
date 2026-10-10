<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Record;

use Beffroi\Core\Application\Record\DeadRecordRemoval;
use Beffroi\Core\Tests\Fixture\DeadRowsOfATable;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #177: the step that drops what can no longer do anything asks each store what it may drop, knows
 * no table, and bounds a run per store.
 */
final class DeadRecordRemovalTest extends TestCase
{
    #[Test]
    public function everyStoreIsAskedAndWhatTheyDroppedIsAddedUp(): void
    {
        // Given
        $first = new DeadRowsOfATable(3);
        $second = new DeadRowsOfATable(4);

        // When
        $forgotten = self::removal([$first, $second])->removeDead(Fixtures::tenant());

        // Then
        static::assertSame(7, $forgotten);
        static::assertSame(1, $first->asked);
        static::assertSame(1, $second->asked);
    }

    /**
     * A store with nothing to drop is not a step that failed, and a step that dropped nothing says so with
     * a number rather than with a store that answered differently.
     */
    #[Test]
    public function aRunThatFindsNothingDropsNothing(): void
    {
        // Given
        $store = new DeadRowsOfATable();

        // When
        $forgotten = self::removal([$store])->removeDead(Fixtures::tenant());

        // Then
        static::assertSame(0, $forgotten);
    }

    /**
     * The budget is per store and not for the whole run: a table with a backlog cannot keep the ones after
     * it from being swept.
     */
    #[Test]
    public function eachStoreGetsTheWholeBudget(): void
    {
        // Given
        $first = new DeadRowsOfATable(10);
        $second = new DeadRowsOfATable(10);

        // When
        $forgotten = self::removal([$first, $second], 2)->removeDead(Fixtures::tenant());

        // Then
        static::assertSame(4, $forgotten);
        static::assertSame(2, $second->limitAsked);
    }

    /**
     * What one run leaves the next takes, the step being recurring and idempotent.
     */
    #[Test]
    public function whatARunLeavesTheNextOneTakes(): void
    {
        // Given
        $store = new DeadRowsOfATable(5);
        $removal = self::removal([$store], 2);
        $removal->removeDead(Fixtures::tenant());
        $removal->removeDead(Fixtures::tenant());

        // When
        $forgotten = $removal->removeDead(Fixtures::tenant());

        // Then
        static::assertSame(1, $forgotten);
        static::assertSame(0, $store->left());
    }

    /**
     * One instant for the whole run, read from the clock and not from each store: two stores that read a
     * clock of their own would sweep two different presents.
     */
    #[Test]
    public function everyStoreIsAskedOfTheSameInstant(): void
    {
        // Given
        $first = new DeadRowsOfATable();
        $second = new DeadRowsOfATable();

        // When
        self::removal([$first, $second])->removeDead(Fixtures::tenant());

        // Then
        static::assertEquals($first->instantAsked, $second->instantAsked);
    }

    /**
     * @param list<DeadRowsOfATable> $stores
     */
    private static function removal(array $stores, int $perRun = DeadRecordRemoval::PER_RUN): DeadRecordRemoval
    {
        return new DeadRecordRemoval($stores, new MockClock(Fixtures::now()), $perRun);
    }
}
