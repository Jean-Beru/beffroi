<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use function array_column;
use Beffroi\Core\Tests\Fixture\Algorithms;
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
                'n' => 'x',
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
                    'n' => 'x',
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
