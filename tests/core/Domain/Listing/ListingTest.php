<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Listing;

use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * One page of a list and how long the list is (architecture §5.2): what a table shows, and what the control
 * under it says of where the reader is.
 */
final class ListingTest extends TestCase
{
    #[Test]
    public function theListingIsTheRowsItHolds(): void
    {
        // Given
        $listing = new Listing(['a', 'b'], new Pagination(1, 2), 5);

        // When / Then
        static::assertSame(['a', 'b'], iterator_to_array($listing));
    }

    #[Test]
    public function theListingCountsTheRowsOfItsOwnPage(): void
    {
        // When / Then
        static::assertCount(2, new Listing(['a', 'b'], new Pagination(1, 2), 5));
    }

    #[Test]
    public function theWholeListIsReadInAsManyPagesAsItTakes(): void
    {
        // When / Then
        static::assertSame(3, new Listing(['a', 'b'], new Pagination(1, 2), 5)->pages());
    }

    #[Test]
    public function aListThatHoldsNothingIsOnePage(): void
    {
        // When / Then
        static::assertSame(1, new Listing([], new Pagination(1, 20), 0)->pages());
    }

    #[Test]
    public function theFirstPageHasNoPageBeforeIt(): void
    {
        // Given
        $listing = new Listing(['a', 'b'], new Pagination(1, 2), 5);

        // When / Then
        static::assertFalse($listing->hasPrevious());
    }

    #[Test]
    public function theLastPageHasNoPageAfterIt(): void
    {
        // Given
        $listing = new Listing(['e'], new Pagination(3, 2), 5);

        // When / Then
        static::assertFalse($listing->hasNext());
    }

    #[Test]
    public function aPageInTheMiddleHasOneOnEitherSide(): void
    {
        // Given
        $listing = new Listing(['c', 'd'], new Pagination(2, 2), 5);

        // Then
        static::assertTrue($listing->hasPrevious());
        static::assertTrue($listing->hasNext());
        static::assertSame(1, $listing->previous());
        static::assertSame(3, $listing->next());
    }

    #[Test]
    public function thePageSaysWhichRowsOfTheWholeListItShows(): void
    {
        // Given
        $listing = new Listing(['c', 'd'], new Pagination(2, 2), 5);

        // Then
        static::assertSame(3, $listing->firstRow());
        static::assertSame(4, $listing->lastRow());
    }

    #[Test]
    public function aPageThatHoldsNoRowShowsNone(): void
    {
        // Given
        $listing = new Listing([], new Pagination(1, 20), 0);

        // Then
        static::assertSame(0, $listing->firstRow());
        static::assertSame(0, $listing->lastRow());
    }

    #[Test]
    public function aListCannotBeShorterThanThePageOfItThatIsRead(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A list of 1 rows cannot hold a page of 2 of them.');

        // When
        new Listing(['a', 'b'], new Pagination(1, 2), 1);
    }
}
