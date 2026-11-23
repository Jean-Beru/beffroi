<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Doctrine\Type\BackupCodesType;
use function array_keys;
use function array_map;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpUsesInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Closure;
use Doctrine\DBAL\Types\Types;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6238 §5.2
 */
final class DoctrineTotpUsesTest extends DatabaseTestCase
{
    private const int STEP = 59_000_000;

    #[Test]
    public function aLaterStepIsWrittenToTheRow(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();

        // When
        self::uses()->acceptStep($totp, self::STEP + 1, self::now());

        // Then
        $found = self::readAgain($totp);
        static::assertSame(self::STEP + 1, $found->lastAcceptedStep);
        static::assertEquals(self::now(), $found->lastUsedAt);
    }

    #[Test]
    public function aStepAnotherRequestWroteSinceTheCredentialWasReadIsRefused(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();
        self::stepWrittenByAnotherRequest($totp, self::STEP + 1);

        // When / Then
        static::assertFalse(self::uses()->acceptStep($totp, self::STEP + 1, self::now()));
    }

    #[Test]
    public function aCredentialRefusedAStepIsLeftAsItWas(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();
        self::stepWrittenByAnotherRequest($totp, self::STEP + 1);

        // When
        self::uses()->acceptStep($totp, self::STEP + 1, self::now());

        // Then
        static::assertSame(self::STEP, $totp->lastAcceptedStep);
        static::assertNull($totp->lastUsedAt);
    }

    #[Test]
    public function aCredentialAcceptedAStepHoldsIt(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();

        // When
        self::uses()->acceptStep($totp, self::STEP + 1, self::now());

        // Then
        static::assertSame(self::STEP + 1, $totp->lastAcceptedStep);
        static::assertEquals(self::now(), $totp->lastUsedAt);
    }

    #[Test]
    public function aStepWrittenIsNotWrittenAgainByALaterFlush(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();
        self::uses()->acceptStep($totp, self::STEP + 1, self::now());
        self::stepWrittenByAnotherRequest($totp, self::STEP + 2);

        // When
        self::entityManager()->flush();

        // Then
        static::assertSame(self::STEP + 2, self::readAgain($totp)->lastAcceptedStep);
    }

    #[Test]
    public function anUnspentBackupCodeIsSpentInTheRow(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();

        // When
        self::uses()->spendBackupCode($totp, 3, self::now());

        // Then
        $found = self::readAgain($totp);
        static::assertEquals(self::now(), $found->backupCodes[3]->usedAt);
        static::assertFalse($found->backupCodes[4]->isSpent());
        static::assertEquals(self::now(), $found->lastUsedAt);
    }

    /**
     * @param Closure(list<BackupCode>): list<BackupCode> $meanwhile
     */
    #[Test]
    #[DataProvider('provideBackupCodesWrittenMeanwhile')]
    public function aBackupCodeIsRefusedWhenAnotherRequestWroteTheCodesSinceTheCredentialWasRead(Closure $meanwhile): void
    {
        // Given
        $totp = self::totpReadFromItsRow();
        self::backupCodesWrittenByAnotherRequest($totp, $meanwhile($totp->backupCodes));

        // When / Then
        static::assertFalse(self::uses()->spendBackupCode($totp, 3, self::now()));
    }

    /**
     * @return iterable<string, array{Closure(list<BackupCode>): list<BackupCode>}>
     */
    public static function provideBackupCodesWrittenMeanwhile(): iterable
    {
        yield 'the same code spent' => [static fn (array $codes): array => self::spentAt($codes, 3)];
        yield 'another code spent' => [static fn (array $codes): array => self::spentAt($codes, 4)];
        yield 'the codes renewed' => [
            static fn (array $codes): array => array_map(
                static fn (BackupCode $code): BackupCode => new BackupCode(new PasswordHash($code->hash->algorithm, 'renewed-' . $code->hash->encoded)),
                $codes,
            ),
        ];
    }

    #[Test]
    public function aCredentialRefusedABackupCodeIsLeftAsItWas(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();
        self::backupCodesWrittenByAnotherRequest($totp, self::spentAt($totp->backupCodes, 3));

        // When
        self::uses()->spendBackupCode($totp, 3, self::now());

        // Then
        static::assertFalse($totp->backupCodes[3]->isSpent());
        static::assertNull($totp->lastUsedAt);
    }

    #[Test]
    public function aCredentialThatSpentABackupCodeHoldsItSpent(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();

        // When
        self::uses()->spendBackupCode($totp, 3, self::now());

        // Then
        static::assertEquals(self::now(), $totp->backupCodes[3]->usedAt);
        static::assertEquals(self::now(), $totp->lastUsedAt);
    }

    #[Test]
    public function aBackupCodeSpentIsNotWrittenAgainByALaterFlush(): void
    {
        // Given
        $totp = self::totpReadFromItsRow();
        self::uses()->spendBackupCode($totp, 3, self::now());
        self::backupCodesWrittenByAnotherRequest($totp, self::spentAt($totp->backupCodes, 4));

        // When
        self::entityManager()->flush();

        // Then
        static::assertTrue(self::readAgain($totp)->backupCodes[4]->isSpent());
    }

    private static function totpReadFromItsRow(): TotpCredential
    {
        $user = self::user();
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), Totps::SEED);
        $totp = new TotpCredential(
            Uuid::v7(),
            $user,
            $sealed,
            Totps::credential($user, new FakePasswordHasher())->backupCodes,
            self::STEP,
            self::now()->modify('-1 day'),
        );
        self::credentials()->save($totp);

        return self::readAgain($totp);
    }

    private static function readAgain(TotpCredential $totp): TotpCredential
    {
        self::reload();
        $found = self::credentials()->find($totp->id);
        static::assertInstanceOf(TotpCredential::class, $found);

        return $found;
    }

    private static function stepWrittenByAnotherRequest(TotpCredential $totp, int $step): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE beffroi_totp_credential SET last_accepted_step = :step WHERE id = :id',
                [
                    'step' => $step,
                    'id' => $totp->id,
                ],
                [
                    'step' => Types::BIGINT,
                    'id' => UuidType::NAME,
                ],
            );
    }

    /**
     * @param list<BackupCode> $codes
     */
    private static function backupCodesWrittenByAnotherRequest(TotpCredential $totp, array $codes): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE beffroi_totp_credential SET backup_codes = :codes WHERE id = :id',
                [
                    'codes' => $codes,
                    'id' => $totp->id,
                ],
                [
                    'codes' => BackupCodesType::NAME,
                    'id' => UuidType::NAME,
                ],
            );
    }

    /**
     * @param list<BackupCode> $codes
     *
     * @return list<BackupCode>
     */
    private static function spentAt(array $codes, int $index): array
    {
        return array_map(
            static fn (int $position, BackupCode $code): BackupCode => $position === $index ? $code->spend(self::now()->modify('-1 minute')) : $code,
            array_keys($codes),
            $codes,
        );
    }

    private static function uses(): TotpUsesInterface
    {
        return self::service('test.beffroi.totp_uses', TotpUsesInterface::class);
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class);
    }
}
