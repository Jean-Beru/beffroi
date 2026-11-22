<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\StoredPasswordHash;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0002
 */
final class StoredPasswordHashTest extends TestCase
{
    private StoredPasswordHash $hashes;

    protected function setUp(): void
    {
        $this->hashes = new StoredPasswordHash(new WiredPasswordAlgorithms([new Argon2id(), new Pbkdf2Sha256()]));
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsAHashAs(PasswordHash $hash, array $document): void
    {
        // When / Then
        static::assertSame($document, $this->hashes->document($hash));
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function aHashComesBackOutOfItsDocument(PasswordHash $hash, array $document): void
    {
        // When / Then
        static::assertEquals($hash, $this->hashes->of($document));
    }

    /**
     * @return iterable<string, array{PasswordHash, array<string, mixed>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a hash this provider made' => [
            new PasswordHash(new Argon2id(), '$argon2id$one'),
            [
                'algorithm' => 'argon2id',
                'encoded' => '$argon2id$one',
                'parameters' => [],
            ],
        ];
        yield 'a hash an import brought' => [
            new PasswordHash(new Pbkdf2Sha256(), 'two', [
                'salt' => 'c2FsdA',
                'iterations' => 27500,
            ]),
            [
                'algorithm' => 'pbkdf2-sha256',
                'encoded' => 'two',
                'parameters' => [
                    'salt' => 'c2FsdA',
                    'iterations' => 27500,
                ],
            ],
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotAHash')]
    public function aDocumentThatIsNotAHashIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->hashes->of($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotAHash(): iterable
    {
        yield 'no algorithm' => [
            [
                'encoded' => 'x',
            ],
            'A password hash names its algorithm and carries its encoded form.',
        ];
        yield 'no digest' => [
            [
                'algorithm' => 'argon2id',
            ],
            'A password hash names its algorithm and carries its encoded form.',
        ];
        yield 'an empty digest' => [
            [
                'algorithm' => 'argon2id',
                'encoded' => '',
            ],
            'A password hash cannot be empty.',
        ];
        yield 'an algorithm nothing wired accounts for' => [
            [
                'algorithm' => 'md5',
                'encoded' => 'x',
            ],
            'This provider accounts for no password hash made with "md5"; it accounts for argon2id, pbkdf2-sha256.',
        ];
        yield 'parameters that are not an object' => [
            [
                'algorithm' => 'argon2id',
                'encoded' => 'x',
                'parameters' => 'salt',
            ],
            'The parameters of a password hash are an object.',
        ];
        yield 'a nested parameter' => [
            [
                'algorithm' => 'argon2id',
                'encoded' => 'x',
                'parameters' => [
                    'salt' => [1],
                ],
            ],
            'The parameters of a password hash map a name to a number or a string.',
        ];
    }
}
