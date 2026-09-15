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
        $credentials = self::credentials();
        $user = self::user();
        $hash = new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'base64digest', [
            'salt' => 'c2FsdA',
            'iterations' => 27500,
        ]);
        $credential = new PasswordCredential(Uuid::v7(), $user, $hash, self::now());
        $credential->markUsed(self::now()->modify('+1 minute'));
        $credentials->save($credential);
        self::reload();

        $found = $credentials->findPasswordCredential($user) ?? static::fail('The credential was not stored.');

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
        static::assertEquals([$found], $credentials->findByUser($user));
    }

    #[Test]
    public function aRehashIsWrittenOnSave(): void
    {
        $credentials = self::credentials();
        $user = self::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), self::now());
        $credentials->save($credential);
        $credential->rehash(new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$new'), self::now()->modify('+1 hour'));
        $credentials->save($credential);
        self::reload();

        $found = $credentials->findPasswordCredential($user) ?? static::fail('The credential was not stored.');

        static::assertSame(PasswordAlgorithm::Argon2id, $found->hash->algorithm);
        static::assertSame('$argon2id$new', $found->hash->encoded);
        static::assertSame([], $found->hash->parameters);
        static::assertEquals(self::now()->modify('+1 hour'), $found->hashChangedAt);
    }

    #[Test]
    public function aUserWithoutPasswordHasNone(): void
    {
        $credentials = self::credentials();
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        $credentials->save(new PasswordCredential(Uuid::v7(), $alice, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), self::now()));
        self::reload();

        static::assertNull($credentials->findPasswordCredential($bob));
        static::assertSame([], $credentials->findByUser($bob));
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.heidi.credentials', CredentialRepositoryInterface::class);
    }
}
