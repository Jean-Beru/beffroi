<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Token\Base64Url;
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
}
