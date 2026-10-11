<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Oidc\Application\Client\StoredClientSecret;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Issue #603: the document the secret of a client is kept as (RFC 7591 §3.2.1), read back without a
 * connection. The document says which of the two shapes the domain has it carries: the digest of a secret
 * the provider cannot read back, or the secret itself, which the one method that computes a MAC with it
 * needs (OIDC Core §9).
 */
final class StoredClientSecretTest extends TestCase
{
    private StoredClientSecret $secrets;

    protected function setUp(): void
    {
        $this->secrets = new StoredClientSecret(new WiredPasswordAlgorithms([new Argon2id()]));
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsASecretAs(ClientSecretInterface $secret, array $document): void
    {
        // When / Then
        static::assertSame($document, $this->secrets->document($secret));
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function aSecretComesBackOutOfItsDocument(ClientSecretInterface $secret, array $document): void
    {
        // When / Then
        static::assertEquals($secret, $this->secrets->of($document));
    }

    /**
     * @return iterable<string, array{ClientSecretInterface, array<string, mixed>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'the secret of a client that presents it' => [
            new HashedClientSecret(new PasswordHash(new Argon2id(), '$argon2id$the-secret-of-a-client')),
            [
                'hash' => [
                    'algorithm' => 'argon2id',
                    'encoded' => '$argon2id$the-secret-of-a-client',
                    'parameters' => [],
                ],
            ],
        ];
        yield 'the secret of a client that signs with it' => [
            new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3'),
            [
                'shared' => 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3',
            ],
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotASecret')]
    public function aDocumentThatIsNotASecretIsRefused(array $document, string $exception, string $message): void
    {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->secrets->of($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, class-string<Throwable>, string}>
     */
    public static function provideDocumentsThatAreNotASecret(): iterable
    {
        yield 'neither shape' => [
            [
                'value' => 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3',
            ],
            InvalidArgumentException::class,
            'A stored client secret carries a "hash" or a "shared" member.',
        ];
        yield 'a hash that is a string' => [
            [
                'hash' => '$argon2id$the-secret-of-a-client',
            ],
            CoreInvalidArgumentException::class,
            'The member "hash" must be a JSON object, got string.',
        ];
        yield 'a hash naming no algorithm' => [
            [
                'hash' => [
                    'encoded' => '$argon2id$the-secret-of-a-client',
                ],
            ],
            CoreInvalidArgumentException::class,
            'A password hash names its algorithm and carries its encoded form.',
        ];
        yield 'a hash naming an algorithm nothing wired accounts for' => [
            [
                'hash' => [
                    'algorithm' => 'md5',
                    'encoded' => 'x',
                ],
            ],
            CoreInvalidArgumentException::class,
            'This provider accounts for no password hash made with "md5"; it accounts for argon2id.',
        ];
    }
}
