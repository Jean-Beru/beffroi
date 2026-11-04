<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use Beffroi\Tui\Screen\Colourway;
use Beffroi\Tui\Screen\TerminalBackground;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The answer of a terminal to OSC 11 with "?": the colour of its background, which says the colourway of the symbol.
 */
final class TerminalBackgroundTest extends TestCase
{
    #[Test]
    #[DataProvider('provideAnswers')]
    public function theColourwayIsTheOneOfTheBackground(string $answer, ?Colourway $colourway): void
    {
        // When / Then
        static::assertSame($colourway, TerminalBackground::colourwayOf($answer));
    }

    /**
     * @return iterable<string, array{string, ?Colourway}>
     */
    public static function provideAnswers(): iterable
    {
        yield 'ink, ended by ST' => ["\e]11;rgb:0c0c/1010/1616\e\\", Colourway::BichromeDark];
        yield 'paper, ended by BEL' => ["\e]11;rgb:f2f2/f4f4/f6f6\x07", Colourway::Bichrome];
        yield 'two digits a channel' => ["\e]11;rgb:1e/1e/2e\e\\", Colourway::BichromeDark];
        yield 'with an alpha channel' => ["\e]11;rgba:ffff/ffff/ffff/ffff\e\\", Colourway::Bichrome];
        yield 'a key the person pressed' => ['q', null];
        yield 'the foreground, not the background' => ["\e]10;rgb:ffff/ffff/ffff\e\\", null];
        yield 'an answer with something after it' => ["\e]11;rgb:0000/0000/0000\e\\q", null];
    }
}
