<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\StoredBackupCodes;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\InvalidArgumentException;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #603: the document the codes of a TOTP are kept as, read back without a connection. Each entry is
 * the document of a password hash and never a second shape of one, and the moment the code was spent at.
 */
final class StoredBackupCodesTest extends TestCase
{
    private StoredBackupCodes $codes;

    protected function setUp(): void
    {
        $this->codes = new StoredBackupCodes(new WiredPasswordAlgorithms([new Argon2id(), new Pbkdf2Sha256()]));
    }

    /**
     * @param list<BackupCode> $set
     * @param list<array<string, mixed>> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsTheCodesAs(array $set, array $document): void
    {
        // When / Then
        static::assertSame($document, $this->codes->document($set));
    }

    /**
     * @param list<BackupCode> $set
     * @param list<array<string, mixed>> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function theCodesComeBackOutOfTheirDocument(array $set, array $document): void
    {
        // When / Then
        static::assertEquals($set, $this->codes->of($document));
    }

    /**
     * @return iterable<string, array{list<BackupCode>, list<array<string, mixed>>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a code drawn and a code spent' => [
            [
                new BackupCode(new PasswordHash(new Argon2id(), '$argon2id$one')),
                new BackupCode(new PasswordHash(new Pbkdf2Sha256(), 'two', [
                    'salt' => 'c2FsdA',
                    'iterations' => 27500,
                ]), new DateTimeImmutable('@1789000060')),
            ],
            [
                [
                    'algorithm' => 'argon2id',
                    'encoded' => '$argon2id$one',
                    'parameters' => [],
                    'used_at' => null,
                ],
                [
                    'algorithm' => 'pbkdf2-sha256',
                    'encoded' => 'two',
                    'parameters' => [
                        'salt' => 'c2FsdA',
                        'iterations' => 27500,
                    ],
                    'used_at' => 1789000060,
                ],
            ],
        ];
        yield 'no code at all' => [[], []];
    }

    /**
     * @param list<mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotCodes')]
    public function aDocumentThatIsNotTheCodesIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->codes->of($document);
    }

    /**
     * @return iterable<string, array{list<mixed>, string}>
     */
    public static function provideDocumentsThatAreNotCodes(): iterable
    {
        yield 'a code that is a string' => [['K7Q2M-X9PL4'], 'The backup code must be a JSON object, got string.'];
        yield 'a code without an algorithm' => [
            [
                [
                    'encoded' => 'x',
                    'used_at' => null,
                ],
            ],
            'A password hash names its algorithm and carries its encoded form.',
        ];
        yield 'a code with an algorithm nothing wired accounts for' => [
            [
                [
                    'algorithm' => 'md5',
                    'encoded' => 'x',
                    'used_at' => null,
                ],
            ],
            'This provider accounts for no password hash made with "md5"; it accounts for argon2id, pbkdf2-sha256.',
        ];
        yield 'a code spent at a moment that is a string' => [
            [
                [
                    'algorithm' => 'argon2id',
                    'encoded' => 'x',
                    'used_at' => '2026-09-20',
                ],
            ],
            'The member "used_at" must be an integer or absent.',
        ];
    }
}
