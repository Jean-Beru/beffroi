<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use function array_column;
use function array_fill;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\RsaModuli;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7517 §5, RFC 7591 §2
 */
final class ClientJwksTest extends TestCase
{
    #[Test]
    public function itReadsTheKeysOfADocument(): void
    {
        // When
        $keys = ClientJwks::fromDocument([
            'keys' => [self::key('one'), self::key('two')],
        ]);

        // Then
        static::assertSame(['one', 'two'], array_column($keys->keys, 'kid'));
    }

    /**
     * RFC 7517 §5
     */
    #[Test]
    public function aSetOfAHundredKeysIsRead(): void
    {
        // When
        $jwks = new ClientJwks(array_fill(0, ClientJwks::MOST_KEYS, [
            'kty' => 'EC',
            'crv' => 'P-256',
        ]));

        // Then
        static::assertCount(ClientJwks::MOST_KEYS, $jwks->keys);
    }

    #[Test]
    public function itFindsAKeyByItsIdentifier(): void
    {
        // Given
        $keys = new ClientJwks([self::key('one'), self::key('two')]);

        // When / Then
        static::assertSame(self::key('two'), $keys->find('two'));
    }

    #[Test]
    public function itHoldsNoKeyItWasNotGiven(): void
    {
        // Given
        $keys = new ClientJwks([self::key('one')]);

        // When / Then
        static::assertFalse($keys->holds('two'));
    }

    /**
     * RFC 7517 §4.2, §4.4
     *
     * @param list<array<string, mixed>> $published
     */
    #[Test]
    #[DataProvider('provideKeysToBeAddressed')]
    public function itChoosesTheKeyAJweIsAddressedTo(array $published, ?string $expected): void
    {
        // Given
        $keys = new ClientJwks($published);

        // When
        $chosen = $keys->encryptionKeyFor(Algorithms::ecdhEsA256Kw());

        // Then
        static::assertSame($expected, $chosen['kid'] ?? null);
    }

    /**
     * @return iterable<string, array{list<array<string, mixed>>, string|null}>
     */
    public static function provideKeysToBeAddressed(): iterable
    {
        yield 'a key that says nothing' => [[self::key('one')], 'one'];
        yield 'a key published for encryption' => [[self::key('one', use: 'enc')], 'one'];
        yield 'a key reserved for signing' => [[self::key('one', use: 'sig')], null];
        yield 'a key of another algorithm' => [[self::key('one', algorithm: 'RSA-OAEP-256')], null];
        yield 'a key of another type' => [
            [[
                'kty' => 'RSA',
                'kid' => 'one',
                'n' => RsaModuli::ofBits(2048),
                'e' => 'AQAB',
            ]],
            null,
        ];
        yield 'the one that names the algorithm, before the one that only says what it is for' => [
            [self::key('one', use: 'enc'), self::key('two', algorithm: 'ECDH-ES+A256KW')],
            'two',
        ];
        yield 'the one published for encryption, before the one that says nothing' => [
            [self::key('one'), self::key('two', use: 'enc')],
            'two',
        ];
        yield 'the first of two that say the same' => [[self::key('one', use: 'enc'), self::key('two', use: 'enc')], 'one'];
        yield 'the first of two that say nothing' => [[self::key('one'), self::key('two')], 'one'];
        yield 'the first of two that name the algorithm' => [
            [self::key('one', algorithm: 'ECDH-ES+A256KW'), self::key('two', algorithm: 'ECDH-ES+A256KW')],
            'one',
        ];
        yield 'past a key of another type' => [
            [
                [
                    'kty' => 'RSA',
                    'kid' => 'one',
                    'n' => RsaModuli::ofBits(2048),
                    'e' => 'AQAB',
                ],
                self::key('two'),
            ],
            'two',
        ];
        yield 'past a key of another algorithm' => [[self::key('one', algorithm: 'ECDH-ES+A128KW'), self::key('two')], 'two'];
        yield 'past a key reserved for signing' => [[self::key('one', use: 'sig'), self::key('two')], 'two'];
        yield 'the signing key of a client that publishes only that' => [[self::key('one', use: 'sig'), self::key('two', algorithm: 'ES256')], null];
    }

    /**
     * @param array<mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotJwkSets')]
    public function itRefusesWhatIsNotAJwkSet(array $document, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        ClientJwks::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<mixed>, string}>
     */
    public static function provideDocumentsThatAreNotJwkSets(): iterable
    {
        yield 'no keys member' => [[], 'object with a "keys" member'];
        yield 'keys not a list' => [
            [
                'keys' => 'no',
            ],
            'object with a "keys" member',
        ];
        yield 'a key that is not an object' => [
            [
                'keys' => ['no'],
            ],
            'Every member of "keys" is a JWK object',
        ];
        yield 'no key at all' => [
            [
                'keys' => [],
            ],
            'holds at least one key',
        ];
        yield 'a hundred and one keys' => [
            [
                'keys' => array_fill(0, ClientJwks::MOST_KEYS + 1, [
                    'kty' => 'EC',
                    'crv' => 'P-256',
                ]),
            ],
            'holds 100 keys at most',
        ];
        yield 'a key without a type' => [
            [
                'keys' => [[
                    'kid' => 'one',
                ]],
            ],
            'names its key type',
        ];
        yield 'a symmetric key (RFC 8725 §3.5)' => [
            [
                'keys' => [[
                    'kty' => 'oct',
                    'k' => 'AAAA',
                ]],
            ],
            'symmetric key in a JWK Set is refused',
        ];
    }

    /**
     * RFC 7518 §3.3, §3.5, §4.3
     *
     * @param array<string, mixed> $key
     */
    #[Test]
    #[DataProvider('provideRsaKeysWithoutAModulusOf2048Bits')]
    public function itRefusesAnRsaKeyThatCarriesNoModulusOf2048Bits(array $key): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An RSA key of a JWK Set carries a modulus "n" of 2048 bits at least (RFC 7518 sections 3.3, 3.5, 4.3 and 6.3.1).');

        // When
        new ClientJwks([self::key('one'), $key]);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideRsaKeysWithoutAModulusOf2048Bits(): iterable
    {
        yield '512 bits' => [self::rsaKey(RsaModuli::ofBits(512))];
        yield '1024 bits' => [self::rsaKey(RsaModuli::ofBits(1024))];
        yield '2047 bits' => [self::rsaKey(RsaModuli::ofBits(2047))];
        yield '2047 bits behind a zero octet (RFC 7518 §6.3.1.1)' => [self::rsaKey(RsaModuli::ofBits(2047, 1))];
        yield 'a modulus that is not base64url' => [self::rsaKey('not/base64+url')];
        yield 'a modulus that is not text' => [self::rsaKey(2048)];
        yield 'no modulus (RFC 7518 §6.3.1)' => [[
            'kty' => 'RSA',
            'kid' => 'rsa',
            'e' => 'AQAB',
        ]];
    }

    /**
     * RFC 7518 §3.3, §3.5, §4.3
     */
    #[Test]
    #[DataProvider('provideRsaModuliOf2048BitsOrMore')]
    public function itHoldsAnRsaKeyOf2048BitsOrMore(string $modulus): void
    {
        // Given
        $key = self::rsaKey($modulus);

        // When
        $keys = new ClientJwks([$key]);

        // Then
        static::assertSame([$key], $keys->keys);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRsaModuliOf2048BitsOrMore(): iterable
    {
        yield '2048 bits' => [RsaModuli::ofBits(2048)];
        yield '2048 bits behind a zero octet (RFC 7518 §6.3.1.1)' => [RsaModuli::ofBits(2048, 1)];
        yield '4096 bits' => [RsaModuli::ofBits(4096)];
    }

    /**
     * RFC 8705 §2.2, RFC 7517 §4.7
     */
    #[Test]
    public function itPublishesTheCertificateOfTheX5cOfAKey(): void
    {
        // Given
        $keys = Certificates::publishedIn(Certificates::selfSigned());

        // When / Then
        static::assertTrue($keys->publishes(Certificates::selfSigned()));
    }

    /**
     * RFC 7517 §4.9
     */
    #[Test]
    public function itPublishesTheCertificateNamedByTheThumbprintOfAKey(): void
    {
        // Given
        $keys = Certificates::thumbprintedIn(Certificates::selfSigned());

        // When / Then
        static::assertTrue($keys->publishes(Certificates::selfSigned()));
    }

    /**
     * RFC 8705 §3.1
     */
    #[Test]
    public function aCertificateReissuedIsNotTheOnePublished(): void
    {
        // Given
        $keys = Certificates::publishedIn(Certificates::selfSigned());

        // When / Then
        static::assertFalse($keys->publishes(Certificates::reissued()));
    }

    #[Test]
    public function aKeyWithoutACertificatePublishesNone(): void
    {
        // Given
        $keys = new ClientJwks([self::key('one')]);

        // When / Then
        static::assertFalse($keys->publishes(Certificates::selfSigned()));
    }

    #[Test]
    public function anUnreadableCertificateChainPublishesNothing(): void
    {
        // Given
        $keys = new ClientJwks([
            self::key('one')
                + [
                    'x5c' => ['!!!!'],
                ],
        ]);

        // When / Then
        static::assertFalse($keys->publishes(Certificates::selfSigned()));
    }

    /**
     * @return array<string, mixed>
     */
    private static function rsaKey(mixed $modulus): array
    {
        return [
            'kty' => 'RSA',
            'kid' => 'rsa',
            'n' => $modulus,
            'e' => 'AQAB',
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function key(string $keyId, ?string $use = null, ?string $algorithm = null): array
    {
        $key = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => $keyId,
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ];
        if ($use !== null) {
            $key['use'] = $use;
        }
        if ($algorithm !== null) {
            $key['alg'] = $algorithm;
        }

        return $key;
    }
}
