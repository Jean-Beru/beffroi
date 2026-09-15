<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

final class Fixtures
{
    public static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-09-15T10:00:00+00:00');
    }

    public static function tenant(string $slug = 'acme', string $issuer = 'https://id.acme.example'): Tenant
    {
        return new Tenant(Uuid::v7(), $slug, new Issuer($issuer), 'Acme', self::now());
    }

    public static function user(?Tenant $tenant = null, string $username = 'alice', string $subject = 'alice-subject'): User
    {
        return User::create(Uuid::v7(), $tenant ?? self::tenant(), new Subject($subject), $username, self::now());
    }
}
