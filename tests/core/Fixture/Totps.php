<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Beffroi\Core\Bridge\Otphp\OtphpTotpAlgorithm;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PasswordHasherInterface;
use function intdiv;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6238 Appendix B
 */
final class Totps
{
    /**
     * RFC 6238 Appendix B
     */
    public const string SEED = '12345678901234567890';

    public const array BACKUP_CODES = [
        'K7Q2M-X9PL4',
        'A3BCD-EFGH2',
        'JKLMN-OPQR3',
        'STUVW-XYZ24',
        'B5CDE-FGHJ6',
        'KLMNP-QRST7',
        'UVWXY-Z234A',
        'CDEFG-HJKL2',
        'MNPQR-STUV3',
        'WXYZ2-34567',
    ];

    private static ?EnvelopeSecretSealer $sealer = null;

    public static function secret(): TotpSecret
    {
        return new TotpSecret(self::SEED);
    }

    public static function sealer(): EnvelopeSecretSealer
    {
        return self::$sealer ??= new EnvelopeSecretSealer(Keys::envelopes(), Keys::KMS_KEY_ID);
    }

    public static function algorithm(): OtphpTotpAlgorithm
    {
        return new OtphpTotpAlgorithm(new MockClock(Fixtures::now()));
    }

    public static function stepAt(DateTimeImmutable $at): int
    {
        return intdiv($at->getTimestamp(), TotpCredential::PERIOD);
    }

    public static function codeAt(DateTimeImmutable $at, ?TotpSecret $secret = null): string
    {
        return self::algorithm()->codeAt($secret ?? self::secret(), self::stepAt($at));
    }

    /**
     * @param list<string> $backupCodes in clear
     */
    public static function credential(
        User $user,
        PasswordHasherInterface $hasher,
        int $lastAcceptedStep = 0,
        array $backupCodes = self::BACKUP_CODES,
        ?TotpSecret $secret = null,
        ?DateTimeImmutable $createdAt = null,
    ): TotpCredential {
        return new TotpCredential(
            Uuid::v7(),
            $user,
            self::sealer()->seal($user->tenant, ($secret ?? self::secret())->bytes),
            array_map(static fn (string $code): BackupCode => new BackupCode($hasher->hash(BackupCode::normalize($code))), $backupCodes),
            $lastAcceptedStep,
            $createdAt ?? Fixtures::now(),
        );
    }
}
