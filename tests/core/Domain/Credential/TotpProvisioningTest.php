<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use function array_slice;
use Beffroi\Core\Domain\Credential\TotpProvisioning;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a TOTP enrolment issues: the secret, the URI and the ten backup codes, nothing stored.
 */
final class TotpProvisioningTest extends TestCase
{
    #[Test]
    public function itCarriesTheSecretTheUriAndTheBackupCodes(): void
    {
        // When
        $provisioning = new TotpProvisioning(
            Totps::secret(),
            'otpauth://totp/Acme%3Aalice?issuer=Acme&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
            Totps::BACKUP_CODES,
        );

        // Then
        static::assertSame(Totps::SEED, $provisioning->secret->bytes);
        static::assertStringStartsWith('otpauth://totp/', $provisioning->uri);
        static::assertSame(Totps::BACKUP_CODES, $provisioning->backupCodes);
    }

    #[Test]
    public function itRefusesAnEmptyUri(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A TOTP provisioning carries the URI the authenticator scans.');

        // When
        new TotpProvisioning(Totps::secret(), '', Totps::BACKUP_CODES);
    }

    #[Test]
    public function itRefusesAnotherNumberOfBackupCodesThanTen(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A TOTP enrolment issues 10 backup codes.');

        // When
        new TotpProvisioning(Totps::secret(), 'otpauth://totp/Acme%3Aalice?secret=X', array_slice(Totps::BACKUP_CODES, 0, 9));
    }
}
