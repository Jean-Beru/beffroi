<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Widget;

use function array_map;
use Beffroi\Tui\Screen\Widget\TableColumn;
use Beffroi\Tui\Screen\Widget\TableWidget;
use function count;
use function max;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function sprintf;
use function str_contains;
use Symfony\Component\Tui\Ansi\AnsiUtils;
use Symfony\Component\Tui\Render\RenderContext;

/**
 * A table is drawn in the room it is given and never more: the rows that fit the height, the columns that fit the
 * width, the ones that matter most kept, and a line that says which rows are shown when they do not all fit.
 */
final class TableWidgetTest extends TestCase
{
    #[Test]
    #[DataProvider('provideRooms')]
    public function aTableNeverDrawsPastTheRoomItIsGiven(int $columns, int $rows): void
    {
        // Given
        $table = self::table(40);

        // When
        $lines = $table->render(new RenderContext($columns, $rows));

        // Then
        static::assertSame([true, true], [count($lines) <= $rows, max([0, ...array_map(AnsiUtils::visibleWidth(...), $lines)]) <= $columns]);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideRooms(): iterable
    {
        yield 'a wide and tall room' => [200, 60];
        yield 'a terminal of 80 by 24' => [80, 24];
        yield 'a narrow one' => [30, 10];
        yield 'two rows' => [60, 2];
    }

    #[Test]
    public function theRowsThatDoNotFitAreSaidWithTheOnesShown(): void
    {
        // Given
        $table = self::table(40);

        // When
        $lines = $table->render(new RenderContext(80, 10));

        // Then
        static::assertStringEndsWith('1-8 / 40', $lines[9]);
    }

    #[Test]
    public function theSelectedRowStaysShownWhenItIsMovedPastTheBottom(): void
    {
        // Given
        $table = self::table(40);
        $table->render(new RenderContext(80, 10));

        // When
        $table->handleInput("\e[F");
        $lines = $table->render(new RenderContext(80, 10));

        // Then
        static::assertSame([39, true], [$table->selected(), str_contains($lines[8], 'row 40')]);
    }

    /**
     * A column is dropped before the ones of a higher priority are cut, whatever its place in the table.
     */
    #[Test]
    public function theColumnOfTheLowestPriorityIsDroppedFirst(): void
    {
        // Given
        $table = new TableWidget([new TableColumn('Low', 10, 0), new TableColumn('High', 10, 9)]);
        $table->setRows([['a low value of some length', 'a high value of some length']]);

        // When
        $lines = $table->render(new RenderContext(30, 5));

        // Then
        static::assertSame([false, true], [str_contains($lines[0], 'Low'), str_contains($lines[0], 'High')]);
    }

    #[Test]
    public function anIdentifierTooWideIsCutInItsMiddle(): void
    {
        // Given
        $table = new TableWidget([new TableColumn('Identifier', 10, 0, middle: true)]);
        $table->setRows([['abcdefghij0123456789']]);

        // When
        $lines = $table->render(new RenderContext(11, 5));

        // Then
        static::assertSame('abcde…56789', AnsiUtils::stripAnsiCodes($lines[1]));
    }

    #[Test]
    public function enterTellsTheRowChosen(): void
    {
        // Given
        $chosen = null;
        $table = self::table(3)
            ->onChoose(static function (int $row) use (&$chosen): void {
                $chosen = $row;
            });

        // When
        $table->handleInput("\e[B");
        $table->handleInput("\r");

        // Then
        static::assertSame(1, $chosen);
    }

    #[Test]
    public function aTableWithoutRowsSaysSo(): void
    {
        // Given
        $table = new TableWidget([new TableColumn('Name')]);
        $table->setRows([], 'Nothing here.');

        // When
        $lines = $table->render(new RenderContext(40, 5));

        // Then
        static::assertSame(['Nothing here.'], array_map(AnsiUtils::stripAnsiCodes(...), $lines));
    }

    private static function table(int $rows): TableWidget
    {
        $table = new TableWidget([new TableColumn('Name', 8, 9), new TableColumn('Value', 8, 1, true)]);
        $table->setRows(array_map(static fn (int $row): array => [sprintf('row %d', $row), (string) ($row * 1000)], range(1, $rows)));

        return $table;
    }
}
