<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Key;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Key\MailSigningKey;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class MailSigningKeyTest extends TestCase
{
    private const string SENDER = 'no-reply@acme.example';

    #[Test]
    #[DataProvider('provideSenderSpellings')]
    public function theCurrentKeySignsForTheSenderItWasSetFor(string $sender): void
    {
        // Given
        $key = self::key();

        // When / Then
        static::assertTrue($key->signsFor(new EmailAddress($sender), Fixtures::now()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSenderSpellings(): iterable
    {
        yield 'as it was set' => [self::SENDER];
        yield 'in capitals' => ['No-Reply@ACME.example'];
    }

    #[Test]
    public function aKeyDoesNotSignForAnotherSender(): void
    {
        // When / Then
        static::assertFalse(self::key()->signsFor(new EmailAddress('alerts@acme.example'), Fixtures::now()));
    }

    #[Test]
    public function aReplacedKeySignsNothing(): void
    {
        // Given
        $key = self::key();

        // When
        $key->replace(Fixtures::now());

        // Then
        static::assertFalse($key->signsFor(new EmailAddress(self::SENDER), Fixtures::now()));
    }

    #[Test]
    public function aKeyPastItsCertificateSignsNothing(): void
    {
        // Given
        $key = self::key(new DateTimeImmutable('2026-09-15T10:00:00+00:00'));

        // When / Then
        static::assertFalse($key->signsFor(new EmailAddress(self::SENDER), Fixtures::now()));
    }

    #[Test]
    public function aKeyReplacedTwiceKeepsTheMomentItWasFirstReplaced(): void
    {
        // Given
        $key = self::key();
        $key->replace(Fixtures::now());

        // When
        $key->replace(Fixtures::now()->modify('+1 day'));

        // Then
        static::assertEquals(Fixtures::now(), $key->replacedAt);
    }

    /**
     * @param list<EmailAddress> $addresses
     */
    #[Test]
    #[DataProvider('provideIncompleteKeys')]
    public function anIncompleteKeyIsRefused(string $kind, string $fingerprint, string $published, array $addresses): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new MailSigningKey(Fixtures::tenant(), $kind, $fingerprint, $published, 'sealed', $addresses, Fixtures::now());
    }

    /**
     * @return iterable<string, array{string, string, string, list<EmailAddress>}>
     */
    public static function provideIncompleteKeys(): iterable
    {
        $sender = [new EmailAddress(self::SENDER)];
        yield 'a format in capitals' => ['SMIME', str_repeat('A', 64), 'public', $sender];
        yield 'a fingerprint in lowercase' => ['smime', str_repeat('a', 64), 'public', $sender];
        yield 'a fingerprint too short' => ['smime', str_repeat('A', 39), 'public', $sender];
        yield 'no public half' => ['smime', str_repeat('A', 64), '', $sender];
        yield 'no sender' => ['smime', str_repeat('A', 64), 'public', []];
    }

    private static function key(?DateTimeImmutable $notAfter = null): MailSigningKey
    {
        return new MailSigningKey(
            Fixtures::tenant(),
            'smime',
            str_repeat('A', 64),
            'public',
            'sealed',
            [new EmailAddress(self::SENDER)],
            Fixtures::now()->modify('-1 day'),
            $notAfter ?? new DateTimeImmutable('2030-01-01T00:00:00+00:00'),
        );
    }
}
