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
    public function itRecordsWhenItWasUsedAndWhenItsHashChanged(): void
    {
        $user = Fixtures::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$old'), Fixtures::now());
        static::assertSame($user->tenant, $credential->tenant);
        static::assertNull($credential->lastUsedAt);
        static::assertEquals(Fixtures::now(), $credential->hashChangedAt);

        $used = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $credential->markUsed($used);
        static::assertSame($used, $credential->lastUsedAt);

        $rehashed = new DateTimeImmutable('2026-09-16T08:00:01+00:00');
        $credential->rehash(new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$new'), $rehashed);
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertSame($rehashed, $credential->hashChangedAt);
        static::assertSame($used, $credential->lastUsedAt);
    }
}
