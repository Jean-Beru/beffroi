<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Exception\InvalidArgumentException;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class MailEncryptionKeyTest extends TestCase
{
    /**
     * RFC 5321 §2.4
     */
    #[Test]
    #[DataProvider('provideSpellingsOfTheSameMailbox')]
    public function itBindsTheMailboxItNamesWhateverItsCase(string $address): void
    {
        // Given
        $key = self::key();

        // When / Then
        static::assertTrue($key->binds(new EmailAddress($address)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpellingsOfTheSameMailbox(): iterable
    {
        yield 'as it names it' => ['alice@acme.example'];
        yield 'in capitals' => ['Alice@ACME.example'];
    }

    #[Test]
    public function itDoesNotBindAnotherMailbox(): void
    {
        // Given
        $key = self::key();

        // When / Then
        static::assertFalse($key->binds(new EmailAddress('mallory@acme.example')));
    }

    #[Test]
    #[DataProvider('provideMomentsOutsideItsValidity')]
    public function itIsNotValidOutsideItsDates(string $moment): void
    {
        // Given
        $key = self::key();

        // When / Then
        static::assertFalse($key->isValidAt(new DateTimeImmutable($moment)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMomentsOutsideItsValidity(): iterable
    {
        yield 'before it begins' => ['2019-12-31T23:59:59+00:00'];
        yield 'the second it ends' => ['2030-01-01T00:00:00+00:00'];
        yield 'after it ends' => ['2031-01-01T00:00:00+00:00'];
    }

    #[Test]
    #[DataProvider('provideMomentsWithinItsValidity')]
    public function itIsValidWithinItsDates(string $moment): void
    {
        // Given
        $key = self::key();

        // When / Then
        static::assertTrue($key->isValidAt(new DateTimeImmutable($moment)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMomentsWithinItsValidity(): iterable
    {
        yield 'the second it begins' => ['2020-01-01T00:00:00+00:00'];
        yield 'in between' => ['2026-09-15T10:00:00+00:00'];
    }

    #[Test]
    public function aKeyWithoutDatesIsValidAtAnyMoment(): void
    {
        // Given
        $key = new MailEncryptionKey('pgp', 'material', 'ABCD', [new EmailAddress('alice@acme.example')]);

        // When / Then
        static::assertTrue($key->isValidAt(new DateTimeImmutable('2126-01-01T00:00:00+00:00')));
    }

    #[Test]
    public function itIsDescribedByItsFormatAndItsFingerprint(): void
    {
        // When / Then
        static::assertSame('smime 9F2C', self::key()->described());
    }

    #[Test]
    public function itIsReadBackFromTheDocumentItWrites(): void
    {
        // Given
        $key = self::key();

        // When
        $read = MailEncryptionKey::fromDocument($key->toDocument());

        // Then
        static::assertEquals($key, $read);
    }

    #[Test]
    #[DataProvider('provideIncompleteKeys')]
    public function anIncompleteKeyIsRefused(string $kind, string $material, string $fingerprint): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new MailEncryptionKey($kind, $material, $fingerprint, []);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideIncompleteKeys(): iterable
    {
        yield 'no format' => ['', 'material', 'ABCD'];
        yield 'no material' => ['smime', '', 'ABCD'];
        yield 'no fingerprint' => ['smime', 'material', ''];
    }

    #[Test]
    public function aKeyThatEndsBeforeItBeginsIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A key mail is encrypted to ends after it begins.');

        // When
        new MailEncryptionKey('smime', 'material', 'ABCD', [], new DateTimeImmutable('2030-01-01'), new DateTimeImmutable('2020-01-01'));
    }

    #[Test]
    public function aDocumentWhoseAddressIsNoStringIsRefused(): void
    {
        // Given
        $document = self::key()->toDocument();
        $document['addresses'] = [42];

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The addresses a key mail is encrypted to names are strings.');

        // When
        MailEncryptionKey::fromDocument($document);
    }

    private static function key(): MailEncryptionKey
    {
        return new MailEncryptionKey(
            'smime',
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
            '9F2C',
            [new EmailAddress('alice@acme.example')],
            new DateTimeImmutable('2020-01-01T00:00:00+00:00'),
            new DateTimeImmutable('2030-01-01T00:00:00+00:00'),
        );
    }
}
