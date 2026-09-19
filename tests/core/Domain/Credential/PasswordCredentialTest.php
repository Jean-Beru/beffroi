<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use DateTimeImmutable;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class PasswordCredentialTest extends TestCase
{
    #[Test]
    public function itBelongsToTheTenantOfItsUserAndStartsUnused(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), Fixtures::now());

        // Then
        static::assertSame($user->tenant, $credential->tenant);
        static::assertNull($credential->lastUsedAt);
        static::assertEquals(Fixtures::now(), $credential->hashChangedAt);
    }

    #[Test]
    public function itNamesItsKindAndHasNoLabel(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), Fixtures::now());

        // When / Then
        static::assertSame('password', $credential->kind());
        static::assertNull($credential->label());
    }

    #[Test]
    public function itRecordsWhenItWasUsed(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');

        // When
        $credential->markUsed($used);

        // Then
        static::assertSame($used, $credential->lastUsedAt);
    }

    #[Test]
    public function aRehashReplacesTheHashAndDatesItWithoutTouchingTheLastUse(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        $rehashed = new DateTimeImmutable('2026-09-16T08:00:01+00:00');

        // When
        $credential->rehash(new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$new'), $rehashed);

        // Then
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertSame($rehashed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }

    #[Test]
    public function aPasswordChangeReplacesTheHashAndDatesItWithoutTouchingTheLastUse(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        $changed = new DateTimeImmutable('2026-09-17T08:00:00+00:00');

        // When
        $credential->changePassword(new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$new'), $changed);

        // Then
        static::assertSame('$argon2id$new', $credential->hash->encoded);
        static::assertSame($changed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }
}
