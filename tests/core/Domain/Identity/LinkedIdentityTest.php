<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Identity;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\LinkedIdentity;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class LinkedIdentityTest extends TestCase
{
    /**
     * Decision 0002: the pair (provider, subject) is what the user is recognised by; the claims are the
     * last snapshot received.
     */
    #[Test]
    public function itRecordsTheUpstreamIdentityOfAUser(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $identity = new LinkedIdentity(
            Uuid::v7(),
            $user,
            'google',
            '1234567890',
            [
                'email' => 'alice@example.com',
            ],
            Fixtures::now(),
            Fixtures::now(),
        );

        // Then
        static::assertSame($user, $identity->user);
        static::assertSame($user->tenant, $identity->tenant);
        static::assertSame('google', $identity->provider);
        static::assertSame('1234567890', $identity->subject);
        static::assertSame(
            [
                'email' => 'alice@example.com',
            ],
            $identity->claims,
        );
    }

    #[Test]
    public function aRefreshReplacesTheSnapshotAndDatesItWithoutTouchingTheLink(): void
    {
        // Given
        $identity = new LinkedIdentity(
            Uuid::v7(),
            Fixtures::user(),
            'google',
            '1234567890',
            [
                'email' => 'alice@example.com',
            ],
            Fixtures::now(),
            Fixtures::now(),
        );
        $later = new DateTimeImmutable('2026-09-16T08:00:00+00:00');

        // When
        $identity->refresh([
            'email' => 'alice@example.org',
        ], $later);

        // Then
        static::assertSame(
            [
                'email' => 'alice@example.org',
            ],
            $identity->claims,
        );
        static::assertSame($later, $identity->lastSeenAt);
        static::assertEquals(Fixtures::now(), $identity->linkedAt);
    }

    #[Test]
    #[DataProvider('provideIncompleteIdentities')]
    public function itNamesItsProviderAndItsSubject(string $provider, string $subject): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new LinkedIdentity(Uuid::v7(), Fixtures::user(), $provider, $subject, [], Fixtures::now(), Fixtures::now());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideIncompleteIdentities(): iterable
    {
        yield 'no provider' => ['', '1234567890'];
        yield 'no subject' => ['google', ''];
    }
}
