<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use function array_filter;
use function array_map;
use function array_slice;
use function array_values;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;
use function str_contains;
use function strtolower;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.1, Decision 0002, RFC 6238 §5.2
 */
final class TotpCredentialTest extends TestCase
{
    private FakePasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
    }

    #[Test]
    public function aUserHoldsATotpWithItsSealedSecretItsBackupCodesAndTheStepOfItsFirstCode(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $totp = Totps::credential($user, $this->hasher, lastAcceptedStep: 59_000_000);

        // Then
        static::assertSame($user, $totp->user);
        static::assertSame($user->tenant, $totp->tenant);
        static::assertSame(Totps::SEED, Totps::sealer()->unseal($user->tenant, $totp->sealedSecret));
        static::assertSame(59_000_000, $totp->lastAcceptedStep);
        static::assertCount(10, $totp->backupCodes);
        static::assertSame([], array_filter($totp->backupCodes, static fn (BackupCode $code): bool => $code->isSpent()));
        static::assertEquals(Fixtures::now(), $totp->createdAt);
        static::assertNull($totp->lastUsedAt);
        static::assertNull($totp->revokedAt);
        static::assertFalse($totp->isRevoked());
    }

    #[Test]
    public function itNamesItsKindAndHasNoLabel(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);

        // When / Then
        static::assertSame('totp', $totp->kind());
        static::assertNull($totp->label());
    }

    /**
     * RFC 8176 §2
     */
    #[Test]
    public function aCodeProvesAOneTimePassword(): void
    {
        // When / Then
        static::assertSame(AuthenticationMethod::ONE_TIME_PASSWORD, TotpCredential::method()->value);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function anAuthenticationWithItMayProveAOneTimePassword(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);

        // When / Then
        static::assertSame(['otp'], array_map(static fn (AuthenticationMethod $method): string => $method->value, $totp->provableMethods()));
    }

    #[Test]
    public function aRevokedOneMayProveNothing(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $totp->revoke(Fixtures::now());

        // When / Then
        static::assertSame([], $totp->provableMethods());
    }

    #[Test]
    public function itHoldsTheSecretSealedAndNothingElseOfIt(): void
    {
        // Given
        $properties = new ReflectionClass(TotpCredential::class)->getProperties();

        // When
        $names = array_map(static fn (ReflectionProperty $property): string => $property->getName(), $properties);

        // Then
        static::assertSame(['sealedSecret'], array_values(array_filter($names, static fn (string $name): bool => str_contains(strtolower($name), 'secret'))));
        static::assertSame([], array_filter($properties, static fn (ReflectionProperty $property): bool => $property->isPrivate() || $property->isProtected()));
    }

    #[Test]
    public function itRefusesAnEmptySealedSecret(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A TOTP credential holds its secret sealed.');

        // When
        new TotpCredential(
            Uuid::v7(),
            Fixtures::user(),
            '',
            array_map(static fn (string $code): BackupCode => new BackupCode(new PasswordHash(new Argon2id(), $code)), Totps::BACKUP_CODES),
            0,
            Fixtures::now(),
        );
    }

    #[Test]
    public function itRefusesAnotherNumberOfBackupCodesThanTen(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A TOTP credential holds 10 backup codes.');

        // When
        Totps::credential(Fixtures::user(), $this->hasher, backupCodes: array_slice(Totps::BACKUP_CODES, 0, 9));
    }

    #[Test]
    public function itRefusesANegativeStep(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A time step is never negative (RFC 6238 §4.2).');

        // When
        Totps::credential(Fixtures::user(), $this->hasher, lastAcceptedStep: -1);
    }

    /**
     * RFC 6238 §5.2
     */
    #[Test]
    #[DataProvider('provideSteps')]
    public function aStepIsAcceptedOnlyAfterTheLastAcceptedOne(int $step, bool $accepted): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher, lastAcceptedStep: 100);

        // When / Then
        static::assertSame($accepted, $totp->acceptsStep($step));
    }

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function provideSteps(): iterable
    {
        yield 'the step before' => [99, false];
        yield 'the same step' => [100, false];
        yield 'the step after' => [101, true];
        yield 'a step much later' => [1_000, true];
    }

    #[Test]
    public function aUseMovesTheAcceptedStepAndDatesTheCredential(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher, lastAcceptedStep: 100);
        $now = Fixtures::now()->modify('+1 day');

        // When
        $totp->recordUse(101, $now);

        // Then
        static::assertSame(101, $totp->lastAcceptedStep);
        static::assertEquals($now, $totp->lastUsedAt);
    }

    #[Test]
    public function aUseAtAStepAlreadyAcceptedIsRefused(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher, lastAcceptedStep: 100);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A TOTP code is accepted once (RFC 6238 §5.2).');

        // When
        $totp->recordUse(100, Fixtures::now());
    }

    #[Test]
    public function aRevokedTotpRecordsNoUse(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $totp->revoke(Fixtures::now());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A revoked totp never authenticates again.');

        // When
        $totp->recordUse(1, Fixtures::now());
    }

    #[Test]
    #[DataProvider('provideBackupCodePositions')]
    public function anUnspentBackupCodeIsHeldOnlyWhereTheListHasOne(int $index, bool $held): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $totp->spendBackupCode(3, Fixtures::now());

        // When / Then
        static::assertSame($held, $totp->holdsUnspentBackupCode($index));
    }

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function provideBackupCodePositions(): iterable
    {
        yield 'an unspent code' => [4, true];
        yield 'a spent code' => [3, false];
        yield 'a position past the list' => [10, false];
    }

    #[Test]
    public function aBackupCodeSpentIsMarkedAndDatesTheCredential(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $now = Fixtures::now()->modify('+1 day');

        // When
        $totp->spendBackupCode(3, $now);

        // Then
        static::assertTrue($totp->backupCodes[3]->isSpent());
        static::assertEquals($now, $totp->backupCodes[3]->usedAt);
        static::assertCount(9, array_filter($totp->backupCodes, static fn (BackupCode $code): bool => ! $code->isSpent()));
        static::assertEquals($now, $totp->lastUsedAt);
    }

    #[Test]
    public function aBackupCodeIsSpentOnce(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $totp->spendBackupCode(3, Fixtures::now());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A backup code is spent once.');

        // When
        $totp->spendBackupCode(3, Fixtures::now()->modify('+1 hour'));
    }

    #[Test]
    public function aBackupCodeOutOfTheListIsRefused(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('There is no backup code at position 10.');

        // When
        $totp->spendBackupCode(10, Fixtures::now());
    }

    #[Test]
    public function aRevokedTotpSpendsNoBackupCode(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $totp->revoke(Fixtures::now());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A revoked totp never authenticates again.');

        // When
        $totp->spendBackupCode(0, Fixtures::now());
    }

    #[Test]
    public function theFirstRevocationWins(): void
    {
        // Given
        $totp = Totps::credential(Fixtures::user(), $this->hasher);
        $totp->revoke(Fixtures::now());

        // When
        $totp->revoke(Fixtures::now()->modify('+1 day'));

        // Then
        static::assertTrue($totp->isRevoked());
        static::assertEquals(Fixtures::now(), $totp->revokedAt);
    }
}
