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
    public function itRecordsTheUpstreamIdentityAndItsLastSnapshot(): void
    {
        $user = Fixtures::user();
        $identity = new LinkedIdentity(Uuid::v7(), $user, 'google', '1234567890', [
            'email' => 'alice@example.com',
        ], Fixtures::now(), Fixtures::now());

        static::assertSame($user, $identity->user);
        static::assertSame($user->tenant, $identity->tenant);
        static::assertSame('google', $identity->provider);
        static::assertSame('1234567890', $identity->subject);
        static::assertSame([
            'email' => 'alice@example.com',
        ], $identity->claims);

        $later = new DateTimeImmutable('2026-09-16T08:00:00+00:00');
        $identity->refresh([
            'email' => 'alice@example.org',
        ], $later);

        static::assertSame([
            'email' => 'alice@example.org',
        ], $identity->claims);
        static::assertSame($later, $identity->lastSeenAt);
        static::assertEquals(Fixtures::now(), $identity->linkedAt);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function incompleteIdentities(): iterable
    {
        yield 'no provider' => ['', '1234567890'];
        yield 'no subject' => ['google', ''];
    }

    #[Test]
    #[DataProvider('incompleteIdentities')]
    public function itNamesItsProviderAndItsSubject(string $provider, string $subject): void
    {
        $this->expectException(InvalidArgumentException::class);

        new LinkedIdentity(Uuid::v7(), Fixtures::user(), $provider, $subject, [], Fixtures::now(), Fixtures::now());
    }
}
