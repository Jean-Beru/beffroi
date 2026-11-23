<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasskeyUsesInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Doctrine\DBAL\Types\Types;
use PHPUnit\Framework\Attributes\Test;
use function random_bytes;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * WebAuthn Level 3 §6.1.1, Decision 0034
 */
final class DoctrinePasskeyUsesTest extends DatabaseTestCase
{
    #[Test]
    public function aCounterThatGrewIsWrittenToTheRowWithTheBackupState(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(5, synced: true);

        // When
        self::uses()->recordUse($passkey, Fixtures::authenticatorData(backupEligible: true, backedUp: true, signCount: 6), self::now());

        // Then
        $found = self::readAgain($passkey);
        static::assertSame(6, $found->signCount);
        static::assertTrue($found->backedUp);
        static::assertEquals(self::now(), $found->lastUsedAt);
    }

    #[Test]
    public function aCounterAnotherAssertionWroteSinceThePasskeyWasReadIsRefused(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(5);
        self::counterWrittenByAnotherAssertion($passkey, 6);

        // When / Then
        static::assertFalse(self::uses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 6), self::now()));
    }

    #[Test]
    public function aCounterAtZeroIsWrittenWhileTheRowHoldsZero(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(0);

        // When
        $written = self::uses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 0), self::now());

        // Then
        static::assertTrue($written);
        static::assertEquals(self::now(), self::readAgain($passkey)->lastUsedAt);
    }

    #[Test]
    public function aCounterAtZeroIsRefusedOnceAnotherAssertionWroteACounter(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(0);
        self::counterWrittenByAnotherAssertion($passkey, 3);

        // When / Then
        static::assertFalse(self::uses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 0), self::now()));
    }

    #[Test]
    public function aPasskeyRefusedIsLeftAsItWas(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(5);
        self::counterWrittenByAnotherAssertion($passkey, 6);

        // When
        self::uses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 6), self::now());

        // Then
        static::assertSame(5, $passkey->signCount);
        static::assertNull($passkey->lastUsedAt);
    }

    #[Test]
    public function aPasskeyAcceptedHoldsTheUse(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(5);

        // When
        self::uses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 6), self::now());

        // Then
        static::assertSame(6, $passkey->signCount);
        static::assertEquals(self::now(), $passkey->lastUsedAt);
    }

    #[Test]
    public function aCounterWrittenIsNotWrittenAgainByALaterFlush(): void
    {
        // Given
        $passkey = self::passkeyReadFromItsRow(5);
        self::uses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 6), self::now());
        self::counterWrittenByAnotherAssertion($passkey, 8);

        // When
        self::entityManager()->flush();

        // Then
        static::assertSame(8, self::readAgain($passkey)->signCount);
    }

    private static function passkeyReadFromItsRow(int $counter, bool $synced = false): PasskeyCredential
    {
        $passkey = new PasskeyCredential(
            Uuid::v7(),
            self::user(),
            'YubiKey 5',
            random_bytes(16),
            'cose-public-key',
            $counter,
            ['usb'],
            $synced,
            false,
            Uuid::v4(),
            Fixtures::userHandle(),
            self::now()->modify('-1 day'),
        );
        self::credentials()->save($passkey);

        return self::readAgain($passkey);
    }

    private static function readAgain(PasskeyCredential $passkey): PasskeyCredential
    {
        self::reload();
        $found = self::credentials()->find($passkey->id);
        static::assertInstanceOf(PasskeyCredential::class, $found);

        return $found;
    }

    private static function counterWrittenByAnotherAssertion(PasskeyCredential $passkey, int $counter): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE beffroi_passkey_credential SET sign_count = :counter WHERE id = :id',
                [
                    'counter' => $counter,
                    'id' => $passkey->id,
                ],
                [
                    'counter' => Types::BIGINT,
                    'id' => UuidType::NAME,
                ],
            );
    }

    private static function uses(): PasskeyUsesInterface
    {
        return self::service('test.beffroi.passkey_uses', PasskeyUsesInterface::class);
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class);
    }
}
