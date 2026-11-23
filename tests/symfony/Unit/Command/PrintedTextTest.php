<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Command;

use App\Command\PrintedText;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a command did not write reaches the terminal as text: neither a sequence the terminal runs nor markup the
 * console formatter obeys.
 */
final class PrintedTextTest extends TestCase
{
    #[Test]
    #[DataProvider('provideWhatATerminalWouldRun')]
    public function whatATerminalWouldRunIsLeftAsVisibleText(string $untrusted, string $shown): void
    {
        // When / Then
        static::assertSame($shown, PrintedText::inBlock($untrusted));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWhatATerminalWouldRun(): iterable
    {
        yield 'a colour' => ["\e[31mred\e[0m", '[31mred[0m'];
        yield 'the title of the window' => ["\e]0;owned\x07 name", ']0;owned name'];
        yield 'the clipboard (OSC 52)' => ["\e]52;c;Y3VybCBldmlsIHwgc2g=\e\\", ']52;c;Y3VybCBldmlsIHwgc2g=\\'];
        yield 'an 8-bit CSI' => ["\u{009B}2Jgone", '2Jgone'];
        yield 'a carriage return over what was written' => ["safe\rforged", 'safeforged'];
        yield 'a right-to-left override' => ["admin\u{202E}nimda", 'adminnimda'];
        yield 'an isolate' => ["\u{2067}evil\u{2069}", 'evil'];
        yield 'a byte that is no UTF-8' => ["caf\xE9", 'caf?'];
    }

    #[Test]
    public function aBlockKeepsItsMarkupAndItsLines(): void
    {
        // When / Then
        static::assertSame("<fg=green>one</>\ttwo\nthree", PrintedText::inBlock("<fg=green>one</>\ttwo\nthree"));
    }

    #[Test]
    #[DataProvider('provideWhatTheFormatterWouldObey')]
    public function whatTheFormatterWouldObeyIsShownAsText(string $untrusted, string $shown): void
    {
        // When / Then
        static::assertSame($shown, PrintedText::of($untrusted));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWhatTheFormatterWouldObey(): iterable
    {
        yield 'a link' => ['<href=https://evil.example>docs</>', '\\<href=https://evil.example\\>docs\\</\\>'];
        yield 'a colour' => ['<fg=black;bg=black>hidden</>', '\\<fg=black;bg=black\\>hidden\\</\\>'];
        yield 'the clipboard (OSC 52)' => ["A client\e]52;c;Y3VybA==\x07", 'A client]52;c;Y3VybA=='];
    }

    #[Test]
    public function aLineHoldsNoBreak(): void
    {
        // When / Then
        static::assertSame('one two three', PrintedText::of("one\ttwo\n\nthree"));
    }
}
