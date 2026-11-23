<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Encoding;

use Beffroi\Core\Domain\Encoding\PlainText;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * OIDC Core §5.1, Unicode Technical Standard #39 §3.1
 */
final class PlainTextTest extends TestCase
{
    #[Test]
    #[DataProvider('providePlainTexts')]
    public function aTextOfALineIsPlain(string $value): void
    {
        // When / Then
        static::assertTrue(PlainText::holds($value, 255));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePlainTexts(): iterable
    {
        yield 'a name with accents' => ['Ada Lovelace-Byrön'];
        yield 'a name in Greek' => ['Ἀριστοτέλης'];
        yield 'a Persian name with a zero-width non-joiner' => ["\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}"];
        yield 'an emoji joined by a zero-width joiner' => ["\u{1F469}\u{200D}\u{1F4BB}"];
        yield 'as long as it may be' => [str_repeat('é', 255)];
    }

    #[Test]
    #[DataProvider('provideTextsThatAreNotPlain')]
    public function aTextThatBreaksReordersOrHidesALineIsNotPlain(string $value): void
    {
        // When / Then
        static::assertFalse(PlainText::holds($value, 255));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTextsThatAreNotPlain(): iterable
    {
        yield 'a line feed' => ["Ada\nLovelace"];
        yield 'an escape sequence' => ["Ada\e[31m"];
        yield 'a NUL byte' => ["Ada\0"];
        yield 'a right-to-left override' => ["Ada\u{202E}gnp.exe"];
        yield 'a bidirectional isolate' => ["Ada\u{2066}"];
        yield 'a zero-width space' => ["Ada\u{200B}Lovelace"];
        yield 'a line separator' => ["Ada\u{2028}Lovelace"];
        yield 'a byte that is not UTF-8' => ["Ada\xFF"];
        yield 'one character too long' => [str_repeat('a', 256)];
    }

    /**
     * OIDC Core §5.1.1
     */
    #[Test]
    #[DataProvider('provideLines')]
    public function linesSeparatedByLineFeedsArePlain(string $value): void
    {
        // When / Then
        static::assertTrue(PlainText::holdsLines($value, 64));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLines(): iterable
    {
        yield 'one line' => ['1 Main Street'];
        yield 'lines separated by a line feed' => ["1 Main Street\nOxford OX1 1AA"];
        yield 'lines separated by a carriage return and a line feed' => ["1 Main Street\r\nOxford OX1 1AA"];
        yield 'as long as they may be, each separator counted' => [str_repeat('a', 30) . "\r\n" . str_repeat('a', 32)];
    }

    /**
     * OIDC Core §5.1.1
     */
    #[Test]
    #[DataProvider('provideLinesThatAreNotPlain')]
    public function linesThatHoldAnythingElseAreNotPlain(string $value): void
    {
        // When / Then
        static::assertFalse(PlainText::holdsLines($value, 64));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLinesThatAreNotPlain(): iterable
    {
        yield 'a carriage return alone' => ["1 Main Street\rOxford"];
        yield 'an escape sequence' => ["1 Main Street\e[2K\nOxford"];
        yield 'a line separator' => ["1 Main Street\u{2028}Oxford"];
        yield 'a paragraph separator' => ["1 Main Street\u{2029}Oxford"];
        yield 'one character too long, each separator counted' => [str_repeat('a', 31) . "\r\n" . str_repeat('a', 32)];
    }
}
