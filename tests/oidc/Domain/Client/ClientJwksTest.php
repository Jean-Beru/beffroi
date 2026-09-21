<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use function array_column;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The keys a client publishes (RFC 7517 §5, RFC 7591 §2), read as they are given and nothing more.
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
        yield 'keys not a list' => [[
            'keys' => 'no',
        ], 'object with a "keys" member'];
        yield 'a key that is not an object' => [[
            'keys' => ['no'],
        ], 'Every member of "keys" is a JWK object'];
        yield 'no key at all' => [[
            'keys' => [],
        ], 'holds at least one key'];
        yield 'a key without a type' => [[
            'keys' => [[
                'kid' => 'one',
            ]],
        ], 'names its key type'];
        yield 'a symmetric key (RFC 8725 §3.5)' => [[
            'keys' => [[
                'kty' => 'oct',
                'k' => 'AAAA',
            ]],
        ], 'symmetric key in a JWK Set is refused'];
    }

    /**
     * RFC 8705 §2.2 and RFC 7517 §4.7: the certificate a client publishes is the first one of the "x5c"
     * of a key of its set, and presenting it is what authenticates the client.
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
     * RFC 7517 §4.9: a key may name its certificate by its thumbprint rather than carry it.
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
     * The certificate is compared and not the key inside it: the same names signed again are another
     * certificate, and it binds tokens to another thumbprint (RFC 8705 §3.1).
     */
    #[Test]
    public function aCertificateReissuedIsNotTheOnePublished(): void
    {
        // Given
        $keys = Certificates::publishedIn(Certificates::selfSigned());

        // When / Then
        static::assertFalse($keys->publishes(Certificates::reissued()));
    }

    /**
     * A client that publishes a public key and no certificate publishes no certificate; nothing is
     * derived from the key to make one.
     */
    #[Test]
    public function aKeyWithoutACertificatePublishesNone(): void
    {
        // Given
        $keys = new ClientJwks([self::key('one')]);

        // When / Then
        static::assertFalse($keys->publishes(Certificates::selfSigned()));
    }

    /**
     * What a client publishes is read as it is given: an "x5c" that is not base64 of a certificate names
     * nobody, and is worth no exception in the middle of an authentication.
     */
    #[Test]
    public function anUnreadableCertificateChainPublishesNothing(): void
    {
        // Given
        $keys = new ClientJwks([self::key('one') + [
            'x5c' => ['!!!!'],
        ]]);

        // When / Then
        static::assertFalse($keys->publishes(Certificates::selfSigned()));
    }

    /**
     * @return array<string, mixed>
     */
    private static function key(string $keyId): array
    {
        return [
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => $keyId,
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ];
    }
}
