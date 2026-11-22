<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.2
 */
final class PendingLoginTest extends TestCase
{
    #[Test]
    public function itHoldsWhoProvedWhatAndExpiresFiveMinutesLater(): void
    {
        // Given
        $userId = Uuid::v7();
        $now = new DateTimeImmutable('2026-09-20T10:00:00+00:00');

        // When
        $login = PendingLogin::provenAt($userId, [AuthenticationMethod::password()], $now);

        // Then
        static::assertSame($userId, $login->userId);
        static::assertEquals([AuthenticationMethod::password()], $login->methods);
        static::assertSame($now, $login->provenAt);
        static::assertEquals(new DateTimeImmutable('2026-09-20T10:05:00+00:00'), $login->expiresAt);
        static::assertFalse($login->isExpired(new DateTimeImmutable('2026-09-20T10:04:59+00:00')));
        static::assertTrue($login->isExpired(new DateTimeImmutable('2026-09-20T10:05:00+00:00')));
    }

    #[Test]
    public function itRefusesToHoldNothingProven(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A pending login holds what its first step proved.');

        // When
        PendingLogin::provenAt(Uuid::v7(), [], new DateTimeImmutable()); // @phpstan-ignore argument.type (the contract is broken on purpose)
    }

    #[Test]
    public function itRefusesToExpireBeforeItsFirstStep(): void
    {
        // Given
        $now = new DateTimeImmutable('2026-09-20T10:00:00+00:00');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A pending login expires after its first step.');

        // When
        new PendingLogin(Uuid::v7(), [AuthenticationMethod::password()], $now, $now);
    }
}
