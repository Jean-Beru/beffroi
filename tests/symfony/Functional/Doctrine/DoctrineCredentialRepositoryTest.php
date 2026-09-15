<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Port\CredentialRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.4: the credentials of a user, the password among them, with a hash that names its
 * algorithm and keeps the parameters of an import (decision 0002).
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
        $found = self::credentials()->findPasswordCredential($user) ?? static::fail('The credential was not stored.');

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
    public function theCredentialsOfAUserAreListed(): void
    {
        // Given
        $user = self::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), self::now());
        self::credentials()->save($credential);
        self::reload();

        // When
        $listed = self::credentials()->findByUser($user);

        // Then
        static::assertCount(1, $listed);
        static::assertTrue($listed[0]->id->equals($credential->id));
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
        $found = self::credentials()->findPasswordCredential($user) ?? static::fail('The credential was not stored.');

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
        static::assertNull(self::credentials()->findPasswordCredential($bob));
        static::assertSame([], self::credentials()->findByUser($bob));
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.heidi.credentials', CredentialRepositoryInterface::class);
    }
}
