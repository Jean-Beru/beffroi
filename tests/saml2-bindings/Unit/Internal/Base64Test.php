<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use function array_map;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Internal\Base64;
use Beffroi\Saml2\Bindings\Internal\Percent;
use function base64_encode;
use function chr;
use function chunk_split;
use function implode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function rtrim;
use function str_replace;

/**
 * B-8, section 6.1 steps 5 and 8, section 6.2 step 4, RFC 4648 §4, §3.5, RFC 2045 §6.8,
 * SAML Bindings §3.4.4.1, §3.5.4
 */
final class Base64Test extends TestCase
{
    use CodecFixtures;

    private const string NOT_CANONICAL = 'A base64 value is not in its one form: the alphabet and the padding of RFC 4648 section 4, the unused bits zero, no whitespace (B-8).';

    /**
     * B-8, RFC 4648 §4
     */
    #[Test]
    #[DataProvider('provideCanonicalTexts')]
    public function itDecodesTheOneForm(string $text, string $expected): void
    {
        // When
        $bytes = Base64::decode($text);

        // Then
        static::assertSame($expected, $bytes);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCanonicalTexts(): iterable
    {
        yield 'no padding' => ['QUJD', 'ABC'];
        yield 'one =' => ['QUI=', 'AB'];
        yield 'two =' => ['QQ==', 'A'];
        yield '+ and /' => ['+/+/', "\xFB\xFF\xBF"];
        yield 'the whole alphabet' => [
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            "\x00\x10\x83\x10\x51\x87\x20\x92\x8B\x30\xD3\x8F\x41\x14\x93\x51\x55\x97\x61\x96\x9B\x71\xD7\x9F\x82\x18\xA3\x92\x59\xA7\xA2\x9A\xAB\xB2\xDB\xAF\xC3\x1C\xB3\xD3\x5D\xB7\xE3\x9E\xBB\xF3\xDF\xBF",
        ];
    }

    /**
     * §9.2 row 25, B-8, B-11, RFC 4648 §3.5 and §5, SAML Bindings §3.4.4.1
     */
    #[Test]
    #[DataProvider('provideTextsNotInTheOneForm')]
    public function itRefusesAValueOfAQueryStringNotInTheOneForm(string $text): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs(self::NOT_CANONICAL);

        // When
        Base64::decode($text);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTextsNotInTheOneForm(): iterable
    {
        yield 'an unused bit set, QR== for QQ==' => ['QR=='];
        yield 'an unused bit set, QUJ= for QUI=' => ['QUJ='];
        yield 'a missing =' => ['QQ='];
        yield 'no padding where it is needed' => ['QQ'];
        yield 'an extra =' => ['QQ==='];
        yield 'an = where none is needed' => ['QUJD='];
        yield 'padding in the middle' => ['QQ==QUJD'];
        yield 'the URL-safe -' => ['-w=='];
        yield 'the URL-safe _' => ['_w=='];
        yield 'a character outside the alphabet' => ['QU*D'];
        yield 'a space' => ['QU JD'];
        yield 'a line feed' => ["QUJD\nQUJD"];
        yield 'a carriage return' => ["QUJD\rQUJD"];
        yield 'a CR LF at the end' => ["QUJD\r\n"];
        yield 'a tab' => ["QU\tJD"];
        yield 'a NUL' => ["QUJD\0"];
    }

    /**
     * §9.2 row 26, B-8, SAML Bindings §3.4.4.1
     */
    #[Test]
    public function itRefusesAPlusLeftUnescapedInAQueryString(): void
    {
        // Given
        $value = Percent::decode('PGE+Pw==');

        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs(self::NOT_CANONICAL);

        // When
        Base64::decode($value);
    }

    /**
     * B-8
     */
    #[Test]
    public function itRefusesAnEmptyValueOfAQueryString(): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A base64 value is empty (B-8).');

        // When
        Base64::decode('');
    }

    /**
     * §9.3 row 9, B-8, RFC 2045 §6.8, SAML Bindings §3.5.4
     */
    #[Test]
    #[DataProvider('provideWrappedTexts')]
    public function itDecodesAValueOfAFormWrappedInLines(string $text): void
    {
        // When
        $bytes = Base64::decodeWrapped($text);

        // Then
        static::assertSame(self::fixture('behaviour/authn-request-unsigned.xml'), $bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWrappedTexts(): iterable
    {
        $text = base64_encode(self::fixture('behaviour/authn-request-unsigned.xml'));

        yield 'wrapped at 76 by CR LF' => [rtrim(chunk_split($text, 76, "\r\n"))];
        yield 'wrapped at 76 by LF' => [rtrim(chunk_split($text, 76, "\n"))];
        yield 'wrapped at 76 by CR LF, a final CR LF' => [chunk_split($text, 76, "\r\n")];
        yield 'on one line' => [$text];
    }

    /**
     * §9.2 row 25, B-8, B-11, RFC 2045 §6.8
     */
    #[Test]
    #[DataProvider('provideWrappedTextsNotInTheOneForm')]
    public function itRefusesAValueOfAFormNotInTheOneForm(string $text): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs(self::NOT_CANONICAL);

        // When
        Base64::decodeWrapped($text);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWrappedTextsNotInTheOneForm(): iterable
    {
        $text = rtrim(chunk_split(base64_encode(self::fixture('behaviour/authn-request-unsigned.xml')), 76, "\r\n"));

        yield 'a space' => [str_replace("\r\n", "\r\n ", $text)];
        yield 'a tab' => [str_replace("\r\n", "\t\r\n", $text)];
        yield 'a vertical tab' => [str_replace("\r\n", "\x0B", $text)];
        yield 'a form feed' => [str_replace("\r\n", "\x0C", $text)];
        yield 'an unused bit set' => ["QR==\r\n"];
        yield 'the URL-safe alphabet' => ["-w==\r\n"];
    }

    /**
     * B-8
     */
    #[Test]
    #[DataProvider('provideEmptyWrappedTexts')]
    public function itRefusesAnEmptyValueOfAForm(string $text): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A base64 value is empty (B-8).');

        // When
        Base64::decodeWrapped($text);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEmptyWrappedTexts(): iterable
    {
        yield 'empty' => [''];
        yield 'a CR LF' => ["\r\n"];
        yield 'line feeds' => ["\n\n"];
        yield 'a carriage return' => ["\r"];
    }

    /**
     * §9.3 rows 11 and 12, sections 6.3 step 3 and 6.4 step 3
     */
    #[Test]
    public function itEncodesOnOneLine(): void
    {
        // Given
        $message = self::fixture('behaviour/authn-request-unsigned.xml');

        // When
        $text = Base64::encode($message);

        // Then
        static::assertDoesNotMatchRegularExpression('~\s~', $text);
        static::assertSame($message, Base64::decode($text));
    }

    /**
     * B-8, RFC 4648 §3.5
     */
    #[Test]
    public function itDecodesWhatItEncodes(): void
    {
        // Given
        $bytes = implode('', array_map(chr(...), range(0, 255)));

        // When
        $decoded = Base64::decode(Base64::encode($bytes));

        // Then
        static::assertSame($bytes, $decoded);
    }
}
