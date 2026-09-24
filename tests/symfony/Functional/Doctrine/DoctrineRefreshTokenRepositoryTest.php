<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.6, §5.3: a token keyed by its hash, its family on every token of the lineage, found by
 * family, by the code the family descends from and by session; rotated and revoked tokens stay.
 */
final class DoctrineRefreshTokenRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aTokenComesBackWithItsFamilyAndWhatTheNextRefreshNeeds(): void
    {
        // Given
        $session = self::session(self::user());
        $client = self::client();
        $family = self::family();
        $claims = new ClaimsRequest([], [
            'acr' => new ClaimRequest(true),
        ]);
        $token = RefreshToken::generate();
        self::tokens()->save(self::token($token, $client, $session, $family, $claims, self::now()->modify('+1 minute')));
        self::reload();

        // When
        $found = self::tokens()->findByTokenHash(RefreshToken::hash($token)) ?? static::fail('The token was not stored.');

        // Then
        static::assertSame(RefreshToken::hash($token), $found->tokenHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertTrue($found->family->id->equals($family->id));
        static::assertSame($family->authorizationCodeHash, $found->family->authorizationCodeHash);
        static::assertEquals($family->startedAt, $found->family->startedAt);
        static::assertEquals($family->expiresAt, $found->family->expiresAt);
        static::assertEquals([new Scope('openid'), new Scope('offline_access')], $found->scopes->all);
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authentication->authenticatedAt);
        static::assertSame(['pwd'], $found->authentication->methods);
        static::assertSame('1', $found->authentication->contextClass);
        static::assertEquals(self::now()->modify('+1 minute'), $found->issuedAt);
        static::assertEquals(self::now()->modify('+30 days'), $found->expiresAt);
        static::assertNull($found->rotatedAt);
        static::assertNull($found->revokedAt);
    }

    #[Test]
    public function aRotationIsWrittenOnSave(): void
    {
        // Given
        $token = self::token(RefreshToken::generate(), self::client(), self::session(self::user()), self::family(), null, self::now()->modify('+1 minute'));
        self::tokens()->save($token);
        $token->rotate(self::now()->modify('+1 hour'));
        self::tokens()->save($token);
        self::reload();

        // When
        $rotated = self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');

        // Then
        static::assertTrue($rotated->isRotated());
        static::assertEquals(self::now()->modify('+1 hour'), $rotated->rotatedAt);
        static::assertFalse($rotated->isRevoked());
    }

    #[Test]
    public function aRevocationIsWrittenOnSave(): void
    {
        // Given
        $token = self::token(RefreshToken::generate(), self::client(), self::session(self::user()), self::family(), null, self::now()->modify('+1 hour'));
        self::tokens()->save($token);
        $token->revoke(self::now()->modify('+2 hours'));
        self::tokens()->save($token);
        self::reload();

        // When
        $revoked = self::tokens()->findByTokenHash($token->tokenHash) ?? static::fail('The token was not stored.');

        // Then
        static::assertTrue($revoked->isRevoked());
        static::assertEquals(self::now()->modify('+2 hours'), $revoked->revokedAt);
    }

    /**
     * RFC 9700 §4.13.2: a reuse revokes the family, found whole, in issuance order.
     */
    #[Test]
    public function tokensAreFoundByFamilyInIssuanceOrder(): void
    {
        // Given
        ['family' => $family, 'first' => $first, 'second' => $second, 'sibling' => $sibling, 'third' => $third] = self::twoFamilies();

        // When / Then
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes(self::tokens()->findByFamily($family->id)));
        static::assertSame([$third->tokenHash], self::hashes(self::tokens()->findByFamily($sibling->id)));
        static::assertSame([], self::hashes(self::tokens()->findByFamily(Uuid::v7())));
    }

    /**
     * RFC 6749 §4.1.2: a replay of the code revokes its descendants, found whole.
     */
    #[Test]
    public function tokensAreFoundByAuthorizationCode(): void
    {
        // Given
        ['family' => $family, 'first' => $first, 'second' => $second] = self::twoFamilies();

        // When / Then
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes(self::tokens()->findByAuthorizationCode($family->authorizationCodeHash)));
    }

    /**
     * Decision 0006: a logout revokes the tokens of the session, found whole.
     */
    #[Test]
    public function tokensAreFoundBySession(): void
    {
        // Given
        ['aliceSession' => $aliceSession, 'first' => $first, 'second' => $second, 'otherSession' => $otherSession, 'third' => $third] = self::twoFamilies();

        // When / Then
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes(self::tokens()->findBySession($aliceSession->id)));
        static::assertSame([$third->tokenHash], self::hashes(self::tokens()->findBySession($otherSession->id)));
        static::assertSame([], self::hashes(self::tokens()->findBySession(Uuid::v7())));
    }

    /**
     * A token of a client removed from the configuration is not a token: not found, so that nothing
     * dereferences a client that does not exist.
     */
    #[Test]
    public function aTokenOfAnUnregisteredClientIsNotFound(): void
    {
        // Given
        ['orphan' => $orphan] = self::anOrphanAndAKeptToken();

        // When / Then
        static::assertNull(self::tokens()->findByTokenHash($orphan->tokenHash));
    }

    /**
     * A token of a client removed from the configuration is not listed either, by family or by session.
     */
    #[Test]
    public function aTokenOfAnUnregisteredClientIsNotListed(): void
    {
        // Given
        ['kept' => $kept, 'family' => $family, 'session' => $session] = self::anOrphanAndAKeptToken();

        // When / Then
        static::assertSame([$kept->tokenHash], self::hashes(self::tokens()->findByFamily($family->id)));
        static::assertSame([$kept->tokenHash], self::hashes(self::tokens()->findBySession($session->id)));
    }

    /**
     * Two tokens of one family in one session of alice, saved out of order, and a third of a sibling
     * family in another session of hers.
     *
     * @return array{family: RefreshTokenFamily, first: RefreshToken, second: RefreshToken, sibling: RefreshTokenFamily, third: RefreshToken, aliceSession: AuthenticationSession, otherSession: AuthenticationSession}
     */
    private static function twoFamilies(): array
    {
        $alice = self::user();
        $aliceSession = self::session($alice);
        $otherSession = self::session($alice, self::now()->modify('+1 minute'));
        $client = self::client();
        $family = self::family();
        $sibling = self::family();
        $first = self::token(RefreshToken::generate(), $client, $aliceSession, $family, null, self::now()->modify('+1 minute'));
        $second = self::token(RefreshToken::generate(), $client, $aliceSession, $family, null, self::now()->modify('+2 minutes'));
        $third = self::token(RefreshToken::generate(), $client, $otherSession, $sibling, null, self::now()->modify('+3 minutes'));
        self::tokens()->save($second);
        self::tokens()->save($first);
        self::tokens()->save($third);
        self::reload();

        return [
            'family' => $family,
            'first' => $first,
            'second' => $second,
            'sibling' => $sibling,
            'third' => $third,
            'aliceSession' => $aliceSession,
            'otherSession' => $otherSession,
        ];
    }

    /**
     * A token of a client removed from the configuration next to one of a registered client, in the
     * same family and the same session.
     *
     * @return array{orphan: RefreshToken, kept: RefreshToken, family: RefreshTokenFamily, session: AuthenticationSession}
     */
    private static function anOrphanAndAKeptToken(): array
    {
        $session = self::session(self::user());
        $family = self::family();
        $ghost = new Client(self::tenant(), 'ghost', 'Removed client', Methods::none(), null, [new RedirectUri('https://ghost.example/callback')]);
        $orphan = self::token(RefreshToken::generate(), $ghost, $session, $family, null, self::now()->modify('+1 minute'));
        $kept = self::token(RefreshToken::generate(), self::client(), $session, $family, null, self::now()->modify('+2 minutes'));
        self::tokens()->save($orphan);
        self::tokens()->save($kept);
        self::reload();

        return [
            'orphan' => $orphan,
            'kept' => $kept,
            'family' => $family,
            'session' => $session,
        ];
    }

    private static function family(): RefreshTokenFamily
    {
        return new RefreshTokenFamily(
            Uuid::v7(),
            AuthorizationCode::hash(AuthorizationCode::generate()),
            Uuid::v7(),
            self::now(),
            self::now()->modify('+90 days'),
        );
    }

    private static function token(
        string $token,
        Client $client,
        AuthenticationSession $session,
        RefreshTokenFamily $family,
        ?ClaimsRequest $claims,
        DateTimeImmutable $issuedAt,
    ): RefreshToken {
        return new RefreshToken(
            RefreshToken::hash($token),
            $family,
            $client,
            $session,
            new Scopes([new Scope('openid'), new Scope('offline_access')]),
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            $issuedAt,
            self::now()->modify('+30 days'),
        );
    }

    /**
     * @param list<RefreshToken> $tokens
     *
     * @return list<string>
     */
    private static function hashes(array $tokens): array
    {
        return array_map(static fn (RefreshToken $token): string => $token->tokenHash, $tokens);
    }

    private static function tokens(): RefreshTokenRepositoryInterface
    {
        return self::service('test.heidi.refresh_tokens', RefreshTokenRepositoryInterface::class);
    }
}
