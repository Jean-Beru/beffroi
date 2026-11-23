<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Encoding;

use Beffroi\Core\Domain\Encoding\JoseExtension;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class JoseExtensionTest extends TestCase
{
    /**
     * RFC 7515 §4.1.11, RFC 7797 §6
     *
     * @param array<string, mixed> $protectedHeader
     */
    #[Test]
    #[DataProvider('provideHeadersThatNameAnExtension')]
    public function aHeaderThatNamesAnExtensionIsSeen(array $protectedHeader): void
    {
        // When / Then
        static::assertTrue(JoseExtension::isNamedIn($protectedHeader));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideHeadersThatNameAnExtension(): iterable
    {
        yield 'a critical parameter' => [[
            'alg' => 'ES256',
            'crit' => ['urn:example:must-understand'],
            'urn:example:must-understand' => true,
        ]];
        yield 'an empty critical list' => [[
            'alg' => 'ES256',
            'crit' => [],
        ]];
        yield 'an unencoded payload named critical' => [[
            'alg' => 'ES256',
            'b64' => false,
            'crit' => ['b64'],
        ]];
        yield 'an unencoded payload not named critical' => [[
            'alg' => 'ES256',
            'b64' => false,
        ]];
        yield 'an encoded payload said so' => [[
            'alg' => 'ES256',
            'b64' => true,
        ]];
    }

    /**
     * RFC 7515 §4.1
     *
     * @param array<string, mixed> $protectedHeader
     */
    #[Test]
    #[DataProvider('provideHeadersOfTheBaseSpecification')]
    public function aHeaderOfTheBaseSpecificationNamesNone(array $protectedHeader): void
    {
        // When / Then
        static::assertFalse(JoseExtension::isNamedIn($protectedHeader));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideHeadersOfTheBaseSpecification(): iterable
    {
        yield 'an algorithm and a key' => [[
            'alg' => 'RS256',
            'kid' => 'key-1',
        ]];
        yield 'a type and a public key' => [[
            'alg' => 'ES256',
            'typ' => 'dpop+jwt',
            'jwk' => [
                'kty' => 'EC',
            ],
        ]];
        yield 'an encryption' => [[
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            'kid' => 'key-1',
        ]];
    }
}
