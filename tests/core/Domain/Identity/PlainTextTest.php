<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\PlainText;
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
}
