<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\MailEncryptionRefusal;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\MailEncryptionRefusedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class UserMailEncryptionTest extends TestCase
{
    private const string ADDRESS = 'alice@acme.example';

    #[Test]
    public function aKeyThatNamesTheVerifiedAddressEncryptsTheMailOfThePerson(): void
    {
        // Given
        $user = self::verified();
        $key = self::key(self::ADDRESS);
        $later = Fixtures::now()->modify('+1 minute');

        // When
        $user->encryptMailTo($key, $later);

        // Then
        static::assertSame($key, $user->mailEncryption);
        static::assertEquals($later, $user->updatedAt);
    }

    #[Test]
    #[DataProvider('provideKeysTheMailIsNotEncryptedTo')]
    public function aKeyTheMailCannotBeEncryptedToIsRefused(
        ?EmailAddress $address,
        bool $verified,
        MailEncryptionKey $key,
        MailEncryptionRefusal $refusal,
    ): void {
        // Given
        $user = Fixtures::user();
        $user->changeEmail($address, $verified, Fixtures::now());

        // When
        try {
            $user->encryptMailTo($key, Fixtures::now());
            static::fail('The key was taken.');
        } catch (MailEncryptionRefusedException $exception) {
            // Then
            static::assertSame($refusal, $exception->refusal);
            static::assertNull($user->mailEncryption);
        }
    }

    /**
     * @return iterable<string, array{?EmailAddress, bool, MailEncryptionKey, MailEncryptionRefusal}>
     */
    public static function provideKeysTheMailIsNotEncryptedTo(): iterable
    {
        yield 'no address' => [null, false, self::key(self::ADDRESS), MailEncryptionRefusal::NoVerifiedAddress];
        yield 'an address nobody verified' => [new EmailAddress(self::ADDRESS), false, self::key(self::ADDRESS), MailEncryptionRefusal::NoVerifiedAddress];
        yield 'a key for another address' => [new EmailAddress(self::ADDRESS), true, self::key('mallory@acme.example'), MailEncryptionRefusal::AnotherAddress];
        yield 'a key that has expired' => [new EmailAddress(self::ADDRESS), true, self::key(self::ADDRESS, '2025-01-01'), MailEncryptionRefusal::NotValidNow];
    }

    #[Test]
    public function aNewAddressTakesTheKeyBack(): void
    {
        // Given
        $user = self::encrypted();

        // When
        $user->changeEmail(new EmailAddress('alice@elsewhere.example'), true, Fixtures::now());

        // Then
        static::assertNull($user->mailEncryption);
    }

    #[Test]
    public function theSameAddressSaidAgainKeepsTheKey(): void
    {
        // Given
        $user = self::encrypted();

        // When
        $user->changeEmail(new EmailAddress(self::ADDRESS), false, Fixtures::now());

        // Then
        static::assertNotNull($user->mailEncryption);
    }

    #[Test]
    public function writingTheMailInClearTakesTheKeyBack(): void
    {
        // Given
        $user = self::encrypted();
        $later = Fixtures::now()->modify('+1 hour');

        // When
        $user->writeMailInClear($later);

        // Then
        static::assertNull($user->mailEncryption);
        static::assertEquals($later, $user->updatedAt);
    }

    #[Test]
    public function writingInClearTheMailOfAPersonWhoAskedNothingChangesNothing(): void
    {
        // Given
        $user = self::verified();
        $updatedAt = $user->updatedAt;

        // When
        $user->writeMailInClear(Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertSame($updatedAt, $user->updatedAt);
    }

    private static function verified(): User
    {
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());

        return $user;
    }

    private static function encrypted(): User
    {
        $user = self::verified();
        $user->encryptMailTo(self::key(self::ADDRESS), Fixtures::now());

        return $user;
    }

    private static function key(string $address, string $notAfter = '2030-01-01'): MailEncryptionKey
    {
        return new MailEncryptionKey(
            'smime',
            'material',
            '9F2C',
            [new EmailAddress($address)],
            new DateTimeImmutable('2020-01-01'),
            new DateTimeImmutable($notAfter),
        );
    }
}
