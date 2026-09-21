<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use function array_column;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Exception\InvalidArgumentException;
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
