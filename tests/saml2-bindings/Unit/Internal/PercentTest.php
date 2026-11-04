<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use function array_map;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Internal\Percent;
use function chr;
use function implode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;

/**
 * B-8, section 6.1 steps 2, 5 and 6, section 6.3 step 3, URL Standard, RFC 3986, SAML Bindings §3.4.4.1
 */
final class PercentTest extends TestCase
{
    /**
     * §9.3 row 2, B-8, RFC 3986 §2.1
     */
    #[Test]
    #[DataProvider('provideEscapes')]
    public function itDecodesAnEscapeOfEitherCase(string $encoded, string $expected): void
    {
        // When
        $decoded = Percent::decode($encoded);

        // Then
        static::assertSame($expected, $decoded);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEscapes(): iterable
    {
        yield 'uppercase' => ['%2F%3D%C3%A9', '/=é'];
        yield 'lowercase' => ['%2f%3d%c3%a9', '/=é'];
        yield 'mixed case' => ['%2f%3D%c3%A9', '/=é'];
        yield 'NUL' => ['%00', "\0"];
        yield 'byte 255' => ['%FF', "\xFF"];
        yield 'an escaped %' => ['%25', '%'];
        yield 'an escaped +' => ['%2B', '+'];
    }

    /**
     * §9.3 row 2, B-8, URL Standard §5
     */
    #[Test]
    #[DataProvider('provideSpaces')]
    public function itDecodesAPlusToASpace(string $encoded): void
    {
        // When
        $decoded = Percent::decode($encoded);

        // Then
        static::assertSame('a relay state', $decoded);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpaces(): iterable
    {
        yield 'written +' => ['a+relay+state'];
        yield 'written %20' => ['a%20relay%20state'];
        yield 'both' => ['a+relay%20state'];
    }

    /**
     * B-8
     */
    #[Test]
    public function itKeepsEveryOtherByte(): void
    {
        // Given
        $encoded = "SAMLRequest-._~/?=&;\x80";

        // When
        $decoded = Percent::decode($encoded);

        // Then
        static::assertSame($encoded, $decoded);
    }

    /**
     * §9.2 row 27, B-8, B-11
     */
    #[Test]
    #[DataProvider('provideMalformedEscapes')]
    public function itRefusesAMalformedEscape(string $encoded): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A percent-escape is not a % followed by two hexadecimal digits (B-8).');

        // When
        Percent::decode($encoded);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedEscapes(): iterable
    {
        yield '%G1' => ['SAML%G1equest'];
        yield '%1G' => ['SAML%1Gequest'];
        yield '%2, one digit' => ['SAMLRequest%2'];
        yield 'a trailing %' => ['SAMLRequest%'];
        yield 'a % alone' => ['%'];
        yield '%%' => ['%%41'];
        yield 'a space after %' => ['% 41'];
        yield 'a sign after %' => ['%+4'];
        yield 'a malformed escape after a well-formed one' => ['%41%4'];
        yield 'a full-width digit after %' => ["%\u{FF14}\u{FF11}"];
    }

    /**
     * §9.3 row 11, section 6.3 step 3, RFC 3986 §2.1 and §2.3
     */
    #[Test]
    #[DataProvider('provideBytes')]
    public function itEncodesEveryByteOutsideTheUnreservedCharacters(string $bytes, string $expected): void
    {
        // When
        $encoded = Percent::encode($bytes);

        // Then
        static::assertSame($expected, $encoded);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBytes(): iterable
    {
        yield 'the unreserved characters' => [
            'ABCXYZabcxyz0189-._~',
            'ABCXYZabcxyz0189-._~',
        ];
        yield 'a space' => [' ', '%20'];
        yield 'the + of base64' => ['+', '%2B'];
        yield 'the / of base64' => ['/', '%2F'];
        yield 'the = of base64' => ['=', '%3D'];
        yield 'the delimiters of a query string' => ['&;?#', '%26%3B%3F%23'];
        yield 'a %' => ['%', '%25'];
        yield 'NUL' => ["\0", '%00'];
        yield 'byte 255, in uppercase' => ["\xFF", '%FF'];
        yield 'é in UTF-8, in uppercase' => ['é', '%C3%A9'];
        yield 'a URI of SigAlg' => [
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256',
        ];
    }

    /**
     * B-8, section 6.3 step 3
     */
    #[Test]
    public function itDecodesWhatItEncodes(): void
    {
        // Given
        $bytes = implode('', array_map(chr(...), range(0, 255)));

        // When
        $decoded = Percent::decode(Percent::encode($bytes));

        // Then
        static::assertSame($bytes, $decoded);
    }
}
