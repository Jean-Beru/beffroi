<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http\Account;

use Beffroi\Bundle\Http\Account\ApplicationHolding;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #451: what one application holds of a person is read from three stores and not from any object of
 * the model. Only what can still be renewed is counted, a rotated, revoked or expired token renewing
 * nothing; and of what waits for that person, this application's is what its page shows.
 */
final class ApplicationHoldingTest extends TestCase
{
    #[Test]
    #[DataProvider('provideTokens')]
    public function itCountsOnlyWhatCanStillBeRenewed(string $state, int $expected): void
    {
        // Given
        $now = Fixtures::now();
        $token = self::token($state, $now);

        // When
        $holding = ApplicationHolding::of(self::consent(), [$token], [], $now);

        // Then
        static::assertSame($expected, $holding->renewable);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideTokens(): iterable
    {
        yield 'issued and untouched' => ['live', 1];
        yield 'rotated by a renewal' => ['rotated', 0];
        yield 'revoked' => ['revoked', 0];
        yield 'past its own expiry' => ['expired', 0];
    }

    #[Test]
    public function theDateItNamesIsTheNewestOfWhatCanStillBeRenewed(): void
    {
        // Given
        $now = Fixtures::now();
        $older = self::token('live', $now, $now->modify('-2 hours'));
        $newer = self::token('live', $now, $now->modify('-1 hour'));

        // When
        $holding = ApplicationHolding::of(self::consent(), [$older, $newer], [], $now);

        // Then
        static::assertSame(2, $holding->renewable);
        static::assertSame($now->modify('-1 hour')->getTimestamp(), $holding->lastIssued?->getTimestamp());
    }

    /**
     * What waits for a person is the answer of the store, every application of theirs together; which of
     * them this page shows is this reading's rule.
     */
    #[Test]
    public function itKeepsOnlyWhatThatApplicationIsWaitingFor(): void
    {
        // Given
        $now = Fixtures::now();
        $session = Fixtures::session();
        $hash = new FakePasswordHasher()->hash(Clients::SECRET);
        $ours = Clients::confidential($session->user->tenant, $hash);
        $theirs = Clients::confidential($session->user->tenant, $hash, clientId: 'another-application');

        // When
        $holding = ApplicationHolding::of(
            self::consent($ours->registration->clientId),
            [],
            [
                Tokens::approvedBackchannelRecord($ours, $session, $now),
                Tokens::approvedBackchannelRecord($theirs, $session, $now),
            ],
            $now,
        );

        // Then
        static::assertCount(1, $holding->pending);
        static::assertSame($ours->registration->clientId, $holding->pending[0]->clientId);
    }

    private static function consent(?string $clientId = null): Consent
    {
        $session = Fixtures::session();
        $client = Clients::confidential($session->user->tenant, new FakePasswordHasher()->hash(Clients::SECRET), clientId: $clientId ?? 'demo-application');

        return new Consent(Uuid::v7(), $session->user, $client, new Scopes([new Scope('openid')]), Fixtures::now());
    }

    private static function token(string $state, DateTimeImmutable $now, ?DateTimeImmutable $issuedAt = null): RefreshToken
    {
        $issuedAt ??= $now->modify('-1 hour');
        $session = Fixtures::session();
        $client = Clients::confidential($session->user->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        if ($state === 'expired') {
            // forty days ago, in a family of its own age: a token lives thirty days at most
            $old = $now->modify('-40 days');

            return Tokens::refreshToken('the-token', $client, $session, $old, Tokens::family($old));
        }
        $token = Tokens::refreshToken('the-token', $client, $session, $issuedAt, Tokens::family($issuedAt));
        if ($state === 'rotated') {
            $token->rotate($now);
        }
        if ($state === 'revoked') {
            $token->revoke($now);
        }

        return $token;
    }
}
