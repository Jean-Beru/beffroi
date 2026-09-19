<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use DateTimeImmutable;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Credential\PasskeyUserHandle;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use function random_bytes;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.4, §5.3: the credentials of a user, one table per kind, the password with a hash that
 * names its algorithm and keeps the parameters of an import (decision 0002), the passkeys with their record.
 */
final class DoctrineCredentialRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aPasswordCredentialComesBackWithItsTypedHash(): void
    {
        // Given
        $user = self::user();
        $hash = new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'base64digest', [
            'salt' => 'c2FsdA',
            'iterations' => 27500,
        ]);
        $credential = new PasswordCredential(Uuid::v7(), $user, $hash, self::now());
        $credential->markUsed(self::now()->modify('+1 minute'));
        self::credentials()->save($credential);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasswordCredential::class)[0] ?? static::fail('The credential was not stored.');

        // Then
        static::assertTrue($found->id->equals($credential->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame(PasswordAlgorithm::Pbkdf2Sha256, $found->hash->algorithm);
        static::assertSame('base64digest', $found->hash->encoded);
        static::assertSame([
            'salt' => 'c2FsdA',
            'iterations' => 27500,
        ], $found->hash->parameters);
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now(), $found->hashChangedAt);
        static::assertEquals(self::now()->modify('+1 minute'), $found->lastUsedAt);
    }

    #[Test]
    public function theCredentialsOfAUserOfEveryKindAreListedOldestFirst(): void
    {
        // Given
        $user = self::user();
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), self::now());
        $passkey = self::passkey($user, createdAt: self::now()->modify('-1 day'));
        self::credentials()->save($password);
        self::credentials()->save($passkey);
        self::reload();

        // When
        $listed = self::credentials()->findByUser($user);

        // Then
        static::assertCount(2, $listed);
        static::assertTrue($listed[0]->id->equals($passkey->id));
        static::assertTrue($listed[1]->id->equals($password->id));
    }

    #[Test]
    public function aPasskeyComesBackWithItsRecordItsNameAndItsDates(): void
    {
        // Given
        $user = self::user();
        $handle = PasskeyUserHandle::generate();
        $credentialId = random_bytes(32);
        $aaguid = Uuid::v4();
        $passkey = new PasskeyCredential(Uuid::v7(), $user, 'Pixel', $credentialId, "\xa5\x01\x02\x03\x26", 7, ['internal', 'hybrid'], true, true, $aaguid, $handle, self::now());
        $passkey->markUsed(self::now()->modify('+1 minute'));
        $passkey->revoke(self::now()->modify('+2 minutes'));
        self::credentials()->save($passkey);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasskeyCredential::class)[0] ?? static::fail('The passkey was not stored.');

        // Then
        static::assertTrue($found->id->equals($passkey->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('Pixel', $found->name);
        static::assertSame($credentialId, $found->credentialId);
        static::assertSame("\xa5\x01\x02\x03\x26", $found->publicKey);
        static::assertSame(7, $found->signCount);
        static::assertSame(['internal', 'hybrid'], $found->transports);
        static::assertTrue($found->backupEligible);
        static::assertTrue($found->backedUp);
        static::assertTrue($found->aaguid->equals($aaguid));
        static::assertTrue($found->userHandle->equals($handle));
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now()->modify('+1 minute'), $found->lastUsedAt);
        static::assertEquals(self::now()->modify('+2 minutes'), $found->revokedAt);
    }

    #[Test]
    public function aUseIsWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $passkey = self::passkey($user);
        self::credentials()->save($passkey);
        $passkey->recordUse(Fixtures::authenticatorData(backupEligible: true, backedUp: true, signCount: 12), self::now()->modify('+1 hour'));
        self::credentials()->save($passkey);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasskeyCredential::class)[0] ?? static::fail('The passkey was not stored.');

        // Then
        static::assertSame(12, $found->signCount);
        static::assertTrue($found->backupEligible);
        static::assertTrue($found->backedUp);
        static::assertEquals(self::now()->modify('+1 hour'), $found->lastUsedAt);
    }

    #[Test]
    public function aCredentialIsFoundByItsIdentifierWhateverItsKind(): void
    {
        // Given
        $user = self::user();
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), self::now());
        $passkey = self::passkey($user);
        self::credentials()->save($password);
        self::credentials()->save($passkey);
        self::reload();

        // When / Then
        static::assertInstanceOf(PasswordCredential::class, self::credentials()->find($password->id));
        static::assertInstanceOf(PasskeyCredential::class, self::credentials()->find($passkey->id));
        static::assertNull(self::credentials()->find(Uuid::v7()));
    }

    #[Test]
    public function aPasskeyIsFoundByItsCredentialIdWithinTheTenant(): void
    {
        // Given
        $user = self::user();
        $credentialId = random_bytes(16);
        $passkey = self::passkey($user, $credentialId);
        self::credentials()->save($passkey);
        self::reload();

        // When
        $found = self::credentials()->findByExternalId(self::tenant(), PasskeyCredential::class, $credentialId);

        // Then
        static::assertNotNull($found);
        static::assertTrue($found->id->equals($passkey->id));
        static::assertNull(self::credentials()->findByExternalId(self::tenant(), PasskeyCredential::class, random_bytes(16)));
    }

    #[Test]
    public function aPasswordHasNoExternalIdentifier(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        self::credentials()->findByExternalId(self::tenant(), PasswordCredential::class, '$argon2id$alice');
    }

    /**
     * WebAuthn Level 3 §7.1, step 26: one credential ID per tenant.
     */
    #[Test]
    public function aSecondPasskeyWithTheSameCredentialIdIsRefusedByTheTable(): void
    {
        // Given
        $credentialId = random_bytes(16);
        self::credentials()->save(self::passkey(self::user(), $credentialId));

        // Then
        $this->expectException(UniqueConstraintViolationException::class);

        // When
        self::credentials()->save(self::passkey(self::user('bob', 'bob-subject'), $credentialId));
    }

    #[Test]
    public function aRehashIsWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), self::now());
        self::credentials()->save($credential);
        $credential->rehash(new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$new'), self::now()->modify('+1 hour'));
        self::credentials()->save($credential);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasswordCredential::class)[0] ?? static::fail('The credential was not stored.');

        // Then
        static::assertSame(PasswordAlgorithm::Argon2id, $found->hash->algorithm);
        static::assertSame('$argon2id$new', $found->hash->encoded);
        static::assertSame([], $found->hash->parameters);
        static::assertEquals(self::now()->modify('+1 hour'), $found->hashChangedAt);
    }

    #[Test]
    public function aUserWithoutPasswordHasNone(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        self::credentials()->save(new PasswordCredential(Uuid::v7(), self::user(), new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), self::now()));
        self::reload();

        // When / Then
        static::assertSame([], self::credentials()->findByUser($bob, PasswordCredential::class));
        static::assertSame([], self::credentials()->findByUser($bob));
    }

    /**
     * A device-bound passkey, with a handle of its own.
     */
    private static function passkey(User $user, ?string $credentialId = null, ?DateTimeImmutable $createdAt = null): PasskeyCredential
    {
        return new PasskeyCredential(Uuid::v7(), $user, 'YubiKey 5', $credentialId ?? random_bytes(16), 'cose-public-key', 0, ['usb'], false, false, Uuid::v4(), PasskeyUserHandle::generate(), $createdAt ?? self::now());
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.heidi.credentials', CredentialRepositoryInterface::class);
    }
}
