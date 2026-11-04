<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use function array_map;
use function count;
use Beffroi\Tui\Screen\Colourway;
use Beffroi\Tui\Screen\Symbol;
use function explode;
use function file_get_contents;
use function max;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function sprintf;
use Symfony\Component\Tui\Ansi\AnsiUtils;

/**
 * The S cut of the terminal support of the brand kit: the 24 columns the kit gives the home screen of a TUI, the 20 and
 * the 11 for a terminal too short, each in its three colourways, drawn as the kit wrote them.
 */
final class SymbolTest extends TestCase
{
    #[Test]
    #[DataProvider('provideTerminalHeights')]
    public function theCutIsTheLargestTheTerminalLeavesRoomFor(int $rows, int $columns): void
    {
        // When
        $symbol = Symbol::fitting($rows, 4);

        // Then
        static::assertSame($columns, $symbol->columns);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideTerminalHeights(): iterable
    {
        yield 'a terminal of 24 rows' => [24, 24];
        yield 'one of 23, the 19 lines and the 4 besides' => [23, 24];
        yield 'one of 22' => [22, 20];
        yield 'one of 20, the 16 lines and the 4 besides' => [20, 20];
        yield 'one of 19' => [19, 11];
        yield 'one too short for any' => [5, 11];
    }

    #[Test]
    #[DataProvider('provideColourways')]
    public function theSymbolIsTheFileOfTheKitAsItIs(Colourway $colourway): void
    {
        // Given
        $file = sprintf('%s/beffroi-symbol-S-24-%s', Symbol::directory(), $colourway->value);

        // When
        $drawn = Symbol::fitting(24, 4)->drawn($colourway);

        // Then
        static::assertSame(rtrim((string) file_get_contents($file), "\n"), $drawn);
    }

    #[Test]
    #[DataProvider('provideColourways')]
    public function theSymbolIsAsWideAsItsCut(Colourway $colourway): void
    {
        // When
        $lines = explode("\n", Symbol::fitting(24, 4)->drawn($colourway));

        // Then
        static::assertSame([19, 24], [count($lines), max(array_map(AnsiUtils::visibleWidth(...), $lines))]);
    }

    /**
     * @return iterable<string, array{Colourway}>
     */
    public static function provideColourways(): iterable
    {
        yield 'mono' => [Colourway::Mono];
        yield 'on a dark terminal' => [Colourway::BichromeDark];
        yield 'on a light terminal' => [Colourway::Bichrome];
    }

    /**
     * The mono cut carries no colour, and the window is cut out of the tower.
     */
    #[Test]
    public function theMonoCutCarriesNoEscapeSequence(): void
    {
        // When
        $drawn = Symbol::fitting(24, 4)->drawn(Colourway::Mono);

        // Then
        static::assertStringNotContainsString("\e", $drawn);
    }
}
