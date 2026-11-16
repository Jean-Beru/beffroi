<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use function array_filter;
use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Domain\Credential\AuthenticatorTransport;
use Beffroi\Core\Domain\Credential\Attestation\AttestationEvidence;
use Beffroi\Core\Domain\Credential\Attestation\VerifiedRegistration;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;
use function str_contains;
use function str_repeat;
use function strtolower;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorData;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Architecture §3.1, §3.2, Decision 0002
 */
final class PasskeyCredentialTest extends TestCase
{
    #[Test]
    public function aUserHoldsAPasswordAndSeveralPasskeysWithOneHandle(): void
    {
        // Given
        $user = Fixtures::user();
        $handle = Fixtures::userHandle();
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Argon2id(), '$argon2id$x'), Fixtures::now());

        // When
        $key = Fixtures::passkey($user, 'YubiKey 5', 'credential-one', $handle);
        $phone = Fixtures::passkey($user, 'Pixel', 'credential-two', $handle, backupEligible: true, backedUp: true);

        // Then
        static::assertSame($user, $password->user);
        static::assertSame($user, $key->user);
        static::assertSame($user, $phone->user);
        static::assertSame($user->tenant, $phone->tenant);
        static::assertTrue($key->userHandle->equals($phone->userHandle));
        static::assertSame('Pixel', $phone->name);
        static::assertSame(0, $phone->signCount);
        static::assertTrue($phone->backupEligible);
        static::assertTrue($phone->backedUp);
        static::assertNull($phone->lastUsedAt);
        static::assertNull($phone->revokedAt);
        static::assertFalse($phone->isRevoked());
    }

    #[Test]
    public function itNamesItsKindAndItsLabelItself(): void
    {
        // Given
        $passkey = Fixtures::passkey(name: 'Pixel');

        // When / Then
        static::assertSame('passkey', $passkey->kind());
        static::assertSame('Pixel', $passkey->label());
    }

    /**
     * WebAuthn Level 3 §6.3.2
     */
    #[Test]
    public function itIsPresentedByItsCredentialId(): void
    {
        // Given
        $passkey = Fixtures::passkey(credentialId: "\x01\x02raw-id");

        // When / Then
        static::assertSame("\x01\x02raw-id", $passkey->externalId);
        static::assertSame($passkey->externalId, $passkey->credentialId);
    }

    /**
     * WebAuthn Level 3 §5.8.4, §5.2.1
     */
    #[Test]
    public function itIsReachedThroughTheTransportsTheSpecificationDefines(): void
    {
        // Given
        $passkey = Fixtures::passkey(transports: ['hybrid', 'cable', 'internal', 'usb']);

        // When
        $reachedThrough = $passkey->reachedThrough;

        // Then
        static::assertSame([AuthenticatorTransport::Hybrid, AuthenticatorTransport::Internal, AuthenticatorTransport::Usb], $reachedThrough);
        static::assertSame(['hybrid', 'cable', 'internal', 'usb'], $passkey->transports);
    }

    #[Test]
    public function itHoldsThePublicKeyAndNoPrivateMember(): void
    {
        // Given
        $properties = new ReflectionClass(PasskeyCredential::class)->getProperties();

        // When
        $names = array_map(static fn (ReflectionProperty $property): string => $property->getName(), $properties);

        // Then
        static::assertContains('publicKey', $names);
        static::assertSame(
            [],
            array_filter($names, static fn (string $name): bool => str_contains(strtolower($name), 'private') || str_contains(strtolower($name), 'secret')),
        );
        static::assertSame([], array_filter($properties, static fn (ReflectionProperty $property): bool => $property->isPrivate() || $property->isProtected()));
    }

    /**
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideFlags')]
    public function anAssertionProvesTheKeyOfThePasskeyAndThePresenceItsFlagsSay(bool $synced, AuthenticatorData $data, array $expected): void
    {
        // Given
        $passkey = Fixtures::passkey(backupEligible: $synced, backedUp: $synced);

        // When
        $methods = $passkey->methods($data);

        // Then
        static::assertSame($expected, array_map(static fn (AuthenticationMethod $method): string => $method->value, $methods));
    }

    /**
     * RFC 8176 §2, WebAuthn Level 3 §6.1, §6.1.3
     *
     * @return iterable<string, array{bool, AuthenticatorData, list<string>}>
     */
    public static function provideFlags(): iterable
    {
        yield 'device-bound key, user present' => [false, Fixtures::authenticatorData(userPresent: true), ['hwk', 'user']];
        yield 'device-bound key, no presence test' => [false, Fixtures::authenticatorData(userPresent: false), ['hwk']];
        yield 'synced passkey, user present' => [true, Fixtures::authenticatorData(userPresent: true, backupEligible: true, backedUp: true), ['swk', 'user']];
        yield 'synced passkey, no presence test' => [true, Fixtures::authenticatorData(userPresent: false, backupEligible: true), ['swk']];
    }

    /**
     * WebAuthn Level 3 §6.2.3, NIST SP 800-63B §3.1.7.1
     */
    #[Test]
    public function aVerifiedUserAddsTheMultipleFactorsMethod(): void
    {
        // Given
        $passkey = Fixtures::passkey();

        // When
        $methods = $passkey->methods(Fixtures::authenticatorData(userPresent: true, userVerified: true));

        // Then
        static::assertSame(['hwk', 'user', 'mfa'], array_map(static fn (AuthenticationMethod $method): string => $method->value, $methods));
    }

    /**
     * Architecture §4.3, WebAuthn Level 3 §7.2 step 16
     */
    #[Test]
    #[DataProvider('provideBackupEligibility')]
    public function anAuthenticationWithItMayProveTheKeyItsBackupEligibilitySaysAndThePresenceOfTheUser(bool $backupEligible, string $key): void
    {
        // Given
        $passkey = Fixtures::passkey(backupEligible: $backupEligible, backedUp: $backupEligible);

        // When / Then
        static::assertSame([$key, 'user'], array_map(static fn (AuthenticationMethod $method): string => $method->value, $passkey->provableMethods()));
    }

    /**
     * @return iterable<string, array{bool, string}>
     */
    public static function provideBackupEligibility(): iterable
    {
        yield 'device-bound key' => [false, 'hwk'];
        yield 'synced passkey' => [true, 'swk'];
    }

    #[Test]
    public function aRevokedOneMayProveNothing(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $passkey->revoke(Fixtures::now());

        // When / Then
        static::assertSame([], $passkey->provableMethods());
    }

    #[Test]
    #[DataProvider('provideSignCounts')]
    public function itTellsASignCountRegressionTheWayWebauthnLibDoes(int $stored, int $received, bool $regresses): void
    {
        // Given
        $passkey = new PasskeyCredential(
            Uuid::v7(),
            Fixtures::user(),
            'key',
            'credential-id',
            'cose',
            $stored,
            [],
            false,
            false,
            Uuid::v4(),
            Fixtures::userHandle(),
            Fixtures::now(),
        );

        // When / Then
        static::assertSame($regresses, $passkey->signCountRegresses(Fixtures::authenticatorData(signCount: $received)));
    }

    /**
     * WebAuthn Level 3 §6.1.1
     *
     * @return iterable<string, array{int, int, bool}>
     */
    public static function provideSignCounts(): iterable
    {
        yield 'both zero, an authenticator that does not count' => [0, 0, false];
        yield 'grows' => [4, 5, false];
        yield 'first use of a counting authenticator' => [0, 1, false];
        yield 'same as stored' => [5, 5, true];
        yield 'below stored' => [5, 3, true];
        yield 'back to zero' => [5, 0, true];
    }

    /**
     * WebAuthn Level 3 §7.2 step 26, §6.1.4
     */
    #[Test]
    public function aUseRecordsTheCountTheBackupStateAndTheDate(): void
    {
        // Given
        $passkey = Fixtures::passkey(backupEligible: true);
        $used = new DateTimeImmutable('2026-09-19T08:00:00+00:00');

        // When
        $passkey->recordUse(Fixtures::authenticatorData(backupEligible: true, backedUp: true, signCount: 7), $used);

        // Then
        static::assertSame(7, $passkey->signCount);
        static::assertTrue($passkey->backupEligible);
        static::assertTrue($passkey->backedUp);
        static::assertSame($used, $passkey->lastUsedAt);
    }

    /**
     * WebAuthn Level 3 §6.1.3
     */
    #[Test]
    #[DataProvider('provideFlippedBackupEligibility')]
    public function aUseThatChangesTheBackupEligibilityIsRefused(bool $enrolledWith): void
    {
        // Given
        $passkey = Fixtures::passkey(backupEligible: $enrolledWith, backedUp: $enrolledWith);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The backup eligibility of a passkey is the one it was enrolled with and never changes (WebAuthn Level 3 §6.1.3).');

        // When
        $passkey->recordUse(Fixtures::authenticatorData(backupEligible: ! $enrolledWith), Fixtures::now());
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideFlippedBackupEligibility(): iterable
    {
        yield 'a synced passkey whose assertion says the key is bound to its authenticator' => [true];
        yield 'a device-bound key whose assertion says the key is synced' => [false];
    }

    #[Test]
    public function aRevokedPasskeyNeverAuthenticatesAgain(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $passkey->revoke(Fixtures::now());

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A revoked passkey never authenticates again.');

        // When
        $passkey->recordUse(Fixtures::authenticatorData(), Fixtures::now()->modify('+1 minute'));
    }

    #[Test]
    public function theFirstRevocationWins(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $first = Fixtures::now();

        // When
        $passkey->revoke($first);
        $passkey->revoke($first->modify('+1 day'));

        // Then
        static::assertTrue($passkey->isRevoked());
        static::assertSame($first, $passkey->revokedAt);
    }

    #[Test]
    public function aBackedUpKeyMustBeEligibleForBackup(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passkey that is not eligible for backup cannot be backed up (WebAuthn Level 3 §6.1.3).');

        // When
        Fixtures::passkey(backupEligible: false, backedUp: true);
    }

    #[Test]
    #[DataProvider('provideNames')]
    public function theNameIsTrimmedAndBounded(string $name, ?string $expected): void
    {
        // Given
        if ($expected === null) {
            $this->expectException(InvalidArgumentException::class);
        }

        // When
        $passkey = Fixtures::passkey(name: $name);

        // Then
        static::assertSame($expected, $passkey->name);
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function provideNames(): iterable
    {
        yield 'trimmed' => ['  Pixel ', 'Pixel'];
        yield 'empty' => ['   ', null];
        yield 'too long' => [str_repeat('n', 256), null];
        yield 'multibyte characters at the bound' => [str_repeat('é', 255), str_repeat('é', 255)];
    }

    #[Test]
    public function itIsBuiltFromTheRecordOfTheRegistrationCeremony(): void
    {
        // Given
        $user = Fixtures::user();
        $handle = Fixtures::userHandle();
        $aaguid = Uuid::v4();
        $record = CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [
                1 => 'internal',
                2 => 'hybrid',
            ],
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            'cose',
            $handle->value,
            3,
            null,
            true,
            true,
            true,
        );

        // When
        $passkey = PasskeyCredential::fromRecord(
            Uuid::v7(),
            $user,
            'Pixel',
            new VerifiedRegistration($record, AttestationEvidence::declared()),
            Fixtures::now(),
        );

        // Then
        static::assertSame('credential-id', $passkey->credentialId);
        static::assertSame('cose', $passkey->publicKey);
        static::assertSame(['internal', 'hybrid'], $passkey->transports);
        static::assertSame(3, $passkey->signCount);
        static::assertTrue($passkey->backupEligible);
        static::assertTrue($passkey->backedUp);
        static::assertTrue($passkey->aaguid->equals($aaguid));
        static::assertTrue($passkey->userHandle->equals($handle));
    }

    #[Test]
    #[DataProvider('provideMissingBackupFlags')]
    public function aRecordWithoutBothBackupFlagsIsRefused(?bool $backupEligible, ?bool $backupStatus): void
    {
        // Given
        $record = CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'cose',
            str_repeat('h', 64),
            0,
            null,
            $backupEligible,
            $backupStatus,
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A passkey is enrolled with the backup flags of its authenticator data (WebAuthn Level 3 §6.1.3).');

        // When
        PasskeyCredential::fromRecord(
            Uuid::v7(),
            Fixtures::user(),
            'Pixel',
            new VerifiedRegistration($record, AttestationEvidence::declared()),
            Fixtures::now(),
        );
    }

    /**
     * @return iterable<string, array{bool|null, bool|null}>
     */
    public static function provideMissingBackupFlags(): iterable
    {
        yield 'neither flag' => [null, null];
        yield 'no backup eligible flag' => [null, false];
        yield 'no backup status flag' => [false, null];
    }

    #[Test]
    public function itGivesTheAuthenticationCeremonyItsRecordWithoutAttestation(): void
    {
        // Given
        $passkey = Fixtures::passkey(credentialId: 'credential-id', backupEligible: true, backedUp: false);
        $passkey->recordUse(Fixtures::authenticatorData(backupEligible: true, signCount: 9), Fixtures::now());

        // When
        $record = $passkey->record();

        // Then
        static::assertSame('credential-id', $record->publicKeyCredentialId);
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $record->type);
        static::assertSame(['usb'], $record->transports);
        static::assertSame('none', $record->attestationType);
        static::assertInstanceOf(EmptyTrustPath::class, $record->trustPath);
        static::assertSame('cose-public-key', $record->credentialPublicKey);
        static::assertSame($passkey->userHandle->value, $record->userHandle);
        static::assertSame(9, $record->counter);
        static::assertTrue($record->backupEligible);
        static::assertFalse($record->backupStatus);
    }
}
