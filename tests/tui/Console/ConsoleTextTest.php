<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Console;

use Beffroi\Tui\Console\ConsoleText;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What the provider wrote reaches a line of the console as text: neither a sequence the terminal runs nor markup the
 * console formatter obeys.
 */
final class ConsoleTextTest extends TestCase
{
    #[Test]
    #[DataProvider('provideWhatTheConsoleWouldObey')]
    public function whatTheConsoleWouldObeyIsShownAsText(string $untrusted, string $shown): void
    {
        // When / Then
        static::assertSame($shown, ConsoleText::of($untrusted));
    }

    /**
     * A block of SymfonyStyle escapes its message itself, so the text it is handed keeps its markup, and loses its
     * controls all the same.
     */
    #[Test]
    public function aBlockIsHandedTheTextCleanedOfItsControlsAlone(): void
    {
        // When / Then
        static::assertSame('register <issuer> <administration API>]0;owned', ConsoleText::inBlock("register <issuer> <administration API>\e]0;owned\x07"));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWhatTheConsoleWouldObey(): iterable
    {
        yield 'a link of the formatter' => ['<href=https://evil.example>client</>', '\\<href=https://evil.example\\>client\\</\\>'];
        yield 'a colour of the formatter' => ['<fg=green>[OK] registered</>', '\\<fg=green\\>[OK] registered\\</\\>'];
        yield 'the clipboard (OSC 52)' => ["refused\e]52;c;Y3VybA==\x07", 'refused]52;c;Y3VybA=='];
        yield 'an erased line' => ["refused\r\e[2K[OK] done", 'refused[2K[OK] done'];
    }
}
