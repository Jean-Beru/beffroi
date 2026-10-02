<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Tests\Fixture\Fixtures;
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
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());

        // Then
        static::assertSame($user->tenant, $credential->tenant);
        static::assertNull($credential->lastUsedAt);
        static::assertEquals(Fixtures::now(), $credential->hashChangedAt);
    }

    #[Test]
    public function itNamesItsKindAndHasNoLabel(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());

        // When / Then
        static::assertSame('password', $credential->kind());
        static::assertNull($credential->label());
    }

    /**
     * RFC 8176 §2: "pwd", what an authentication with a password may prove (architecture §4.3).
     */
    #[Test]
    public function anAuthenticationWithItMayProveAPassword(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());

        // When / Then
        static::assertSame(['pwd'], array_map(static fn (AuthenticationMethod $method): string => $method->value, $credential->provableMethods()));
    }

    #[Test]
    public function itRecordsWhenItWasUsed(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());
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
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Bcrypt(), '$2y$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        $rehashed = new DateTimeImmutable('2026-09-16T08:00:01+00:00');

        // When
        $credential->rehash(new PasswordHash(new Argon2id(), '$argon2id$new'), $rehashed);

        // Then
        static::assertSame(Argon2id::NAME, $credential->hash->algorithm->name());
        static::assertSame($rehashed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }

    #[Test]
    public function aPasswordChangeReplacesTheHashAndDatesItWithoutTouchingTheLastUse(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), Fixtures::user(), new PasswordHash(new Argon2id(), '$argon2id$old'), Fixtures::now());
        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        $changed = new DateTimeImmutable('2026-09-17T08:00:00+00:00');

        // When
        $credential->changePassword(new PasswordHash(new Argon2id(), '$argon2id$new'), $changed);

        // Then
        static::assertSame('$argon2id$new', $credential->hash->encoded);
        static::assertSame($changed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }
}
