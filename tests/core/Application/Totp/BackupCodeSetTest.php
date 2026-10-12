<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Totp;

use function array_unique;
use Beffroi\Core\Application\Totp\BackupCodeSet;
use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.4: the set of backup codes the enrolment of a TOTP and the renewal of its codes both
 * draw, drawn where every secret of this provider is and hashed as a password is.
 */
final class BackupCodeSetTest extends TestCase
{
    private FakePasswordHasher $hasher;

    private BackupCodeSet $codes;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
        $this->codes = new BackupCodeSet(new FixedRandomness(), $this->hasher);
    }

    #[Test]
    public function itDrawsAsManyDistinctCodesAsACredentialHolds(): void
    {
        // When
        $spelled = $this->codes->draw();

        // Then
        static::assertCount(TotpCredential::BACKUP_CODES, $spelled);
        static::assertCount(TotpCredential::BACKUP_CODES, array_unique($spelled));
    }

    /**
     * The alphabet of RFC 4648 §6 in two groups of five, which is what BackupCode::spelledBy() makes of
     * the bytes it is handed: a code is drawn from LENGTH bytes and spelled in one place.
     */
    #[Test]
    public function aCodeIsTheBytesItWasDrawnFromSpelled(): void
    {
        // Given
        $codes = new BackupCodeSet(new FixedRandomness(["\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"]), $this->hasher);

        // When
        $spelled = $codes->draw();

        // Then
        static::assertSame(BackupCode::spelledBy("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"), $spelled[0]);
    }

    /**
     * What a credential holds of a set: the hash of every code, in the order they were drawn.
     */
    #[Test]
    public function itHashesEveryCodeOfASetInTheOrderTheyWereDrawn(): void
    {
        // Given
        $spelled = $this->codes->draw();

        // When
        $hashed = $this->codes->hashed($spelled);

        // Then
        static::assertCount(TotpCredential::BACKUP_CODES, $hashed);
        foreach ($spelled as $index => $one) {
            static::assertTrue($this->hasher->verify($hashed[$index]->hash, BackupCode::normalize($one)));
        }
    }
}
