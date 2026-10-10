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
     * RFC 4648 §10 test vectors, with the padding of §5 removed, and RFC 7515 appendix C: the alphabet
     * uses "-" and "_" where base64 uses "+" and "/".
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
     * What a store reads out of a column it did not write is a text somebody else may have written.
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
    }
}
