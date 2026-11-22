<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Listing;

use Beffroi\Core\Domain\Listing\Pagination;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.2
 */
final class PaginationTest extends TestCase
{
    #[Test]
    public function thePageSkipsTheRowsOfThePagesBeforeIt(): void
    {
        // When / Then
        static::assertSame(40, new Pagination(3, 20)->offset());
    }

    #[Test]
    public function theFirstPageSkipsNothing(): void
    {
        // When / Then
        static::assertSame(0, new Pagination(1, 20)->offset());
    }

    #[Test]
    #[DataProvider('provideNumbersThatAreNotAPage')]
    public function aPageIsNumberedFromOne(int $number): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('A page is numbered from 1, "%d" given.', $number));

        // When
        new Pagination($number, 20);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideNumbersThatAreNotAPage(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    #[Test]
    public function aPageHoldsOneRowOrMore(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A page holds one row or more, "0" given.');

        // When
        new Pagination(1, 0);
    }

    #[Test]
    public function aPagePastTheLastOneIsTheLastOne(): void
    {
        // When
        $held = new Pagination(9, 20)->within(45);

        // Then
        static::assertSame(3, $held->number);
        static::assertSame(20, $held->size);
    }

    #[Test]
    public function aPageInsideTheListIsTheOneThatWasAsked(): void
    {
        // When / Then
        static::assertSame(2, new Pagination(2, 20)->within(45)->number);
    }

    #[Test]
    public function aListThatHoldsNothingIsOnePage(): void
    {
        // When / Then
        static::assertSame(1, new Pagination(4, 20)->within(0)->number);
    }
}
