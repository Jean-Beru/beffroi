<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Encoding;

use Beffroi\Core\Domain\Encoding\Base64Url;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    /**
     * RFC 4648 §10, §5, RFC 7515 appendix C
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itEncodesWithoutPaddingInTheUrlSafeAlphabet(string $octets, string $expected): void
    {
        // When / Then
        static::assertSame($expected, Base64Url::encode($octets));
    }

    #[Test]
    #[DataProvider('provideVectors')]
    public function itReadsBackWhatItWrote(string $octets, string $encoded): void
    {
        // When / Then
        static::assertSame($octets, Base64Url::decode($encoded));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideVectors(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'f' => ['f', 'Zg'];
        yield 'fo' => ['fo', 'Zm8'];
        yield 'foo' => ['foo', 'Zm9v'];
        yield 'foob' => ['foob', 'Zm9vYg'];
        yield 'fooba' => ['fooba', 'Zm9vYmE'];
        yield 'foobar' => ['foobar', 'Zm9vYmFy'];
        yield 'RFC 7515 appendix C' => ["\x03\xd3\xff\xbf\x03", 'A9P_vwM'];
        yield 'both substituted characters' => ["\xfb\xff", '-_8'];
    }

    /**
     * RFC 4648 §4, §5
     */
    #[Test]
    #[DataProvider('provideTextsThatAreNotBase64Url')]
    public function aTextThatIsNotBase64UrlIsNotRead(string $encoded): void
    {
        // When / Then
        static::assertNull(Base64Url::decode($encoded));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTextsThatAreNotBase64Url(): iterable
    {
        yield 'outside the alphabet' => ['***'];
        yield 'one character outside it' => ['Zm9v*'];
        yield 'a character of no alphabet at all' => ["Zm9v\x00"];
        yield 'the "+" of the standard alphabet' => ['Zm+v'];
        yield 'the "/" of the standard alphabet' => ['Zm/v'];
        yield 'padded' => ['Zm8='];
        yield 'padded to the full quantum' => ['Zg=='];
        yield 'the padding alone' => ['='];
        yield 'a line a reader wrapped' => ["Zm9v\nYmFy"];
        yield 'a trailing line feed' => ["Zm9v\n"];
        yield 'a space between two quanta' => ['Zm9v YmFy'];
        yield 'a quantum of one character' => ['Zm9vY'];
    }
}
