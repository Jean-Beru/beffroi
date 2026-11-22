<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Support;

use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * model.md section 5.2, M-11
 */
final class InMemoryReplayGuardTest extends TestCase
{
    /**
     * model.md section 5.2
     */
    #[Test]
    public function itRemembersAPairItHasNotSeen(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();

        // When
        $new = $guard->remember(
            'https://idp.example.com/saml',
            '_assertion',
            new DateTimeImmutable('2026-09-30T12:08:00Z'),
        );

        // Then
        static::assertTrue($new);
    }

    /**
     * M-11
     */
    #[Test]
    public function itAnswersFalseForAPairItHasSeen(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When
        $new = $guard->remember(
            'https://idp.example.com/saml',
            '_assertion',
            new DateTimeImmutable('2026-09-30T12:09:00Z'),
        );

        // Then
        static::assertFalse($new);
    }

    /**
     * M-11
     */
    #[Test]
    public function itRemembersTheSameIdFromAnotherIssuer(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When
        $new = $guard->remember(
            'https://other-idp.example.com/saml',
            '_assertion',
            new DateTimeImmutable('2026-09-30T12:08:00Z'),
        );

        // Then
        static::assertTrue($new);
    }

    /**
     * M-11
     */
    #[Test]
    public function itRemembersAnotherIdFromTheSameIssuer(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When
        $new = $guard->remember(
            'https://idp.example.com/saml',
            '_other',
            new DateTimeImmutable('2026-09-30T12:08:00Z'),
        );

        // Then
        static::assertTrue($new);
    }

    /**
     * model.md section 5.2
     */
    #[Test]
    public function itKeepsTheExpiryItWasFirstGiven(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T13:00:00Z'));

        // When
        $expiresAt = $guard->expiresAt('https://idp.example.com/saml', '_assertion');

        // Then
        static::assertSame('2026-09-30T12:08:00Z', $expiresAt?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * model.md section 5.2
     */
    #[Test]
    public function itHasNoExpiryForAPairNeverRemembered(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When / Then
        static::assertNull($guard->expiresAt('https://other-idp.example.com/saml', '_assertion'));
    }

    /**
     * M-11
     */
    #[Test]
    public function itIsEmptyUntilAPairIsRemembered(): void
    {
        // When / Then
        static::assertTrue(new InMemoryReplayGuard()->isEmpty());
    }

    /**
     * M-11
     */
    #[Test]
    public function itIsNotEmptyOnceAPairIsRemembered(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();

        // When
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // Then
        static::assertFalse($guard->isEmpty());
    }
}
