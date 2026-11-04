<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Text;

use Beffroi\Tui\Text\TerminalText;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a third party wrote reaches the terminal as text, never as a sequence the terminal runs (decision 0038:
 * the administration shows what others registered).
 */
final class TerminalTextTest extends TestCase
{
    #[Test]
    #[DataProvider('provideWhatATerminalWouldRun')]
    public function whatATerminalWouldRunIsLeftAsVisibleText(string $untrusted, string $shown): void
    {
        // When / Then
        static::assertSame($shown, TerminalText::of($untrusted)->value);
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
    public function aTabAndALineBreakStayInText(): void
    {
        // When / Then
        static::assertSame("one\ttwo\nthree", TerminalText::of("one\ttwo\nthree")->value);
    }

    #[Test]
    public function aLineHoldsNoBreak(): void
    {
        // When / Then
        static::assertSame('one two three', TerminalText::line("one\ttwo\n\nthree")->value);
    }
}
