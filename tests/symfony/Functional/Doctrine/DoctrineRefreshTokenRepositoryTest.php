<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
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
        $tokens = self::tokens();
        $session = self::session(self::user());
        $client = self::client();
        $family = self::family();
        $claims = new ClaimsRequest([], [
            'acr' => new ClaimRequest(true),
        ]);
        $token = RefreshToken::generate();
        $tokens->save(self::token($token, $client, $session, $family, $claims, self::now()->modify('+1 minute')));
        self::reload();

        $found = $tokens->findByTokenHash(RefreshToken::hash($token)) ?? static::fail('The token was not stored.');

        static::assertSame(RefreshToken::hash($token), $found->tokenHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertTrue($found->family->id->equals($family->id));
        static::assertSame($family->authorizationCodeHash, $found->family->authorizationCodeHash);
        static::assertEquals($family->startedAt, $found->family->startedAt);
        static::assertEquals($family->expiresAt, $found->family->expiresAt);
        static::assertEquals([new Scope('openid'), new Scope('offline_access')], $found->scopes);
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authenticatedAt);
        static::assertSame(['pwd'], $found->authenticationMethods);
        static::assertNull($found->authenticationContextClass);
        static::assertEquals(self::now()->modify('+1 minute'), $found->issuedAt);
        static::assertEquals(self::now()->modify('+30 days'), $found->expiresAt);
        static::assertNull($found->rotatedAt);
        static::assertNull($found->revokedAt);
    }

    #[Test]
    public function aRotationAndARevocationAreWrittenOnSave(): void
    {
        $tokens = self::tokens();
        $session = self::session(self::user());
        $client = self::client();
        $family = self::family();
        $first = self::token(RefreshToken::generate(), $client, $session, $family, null, self::now()->modify('+1 minute'));
        $tokens->save($first);
        $first->rotate(self::now()->modify('+1 hour'));
        $tokens->save($first);
        $second = self::token(RefreshToken::generate(), $client, $session, $family, null, self::now()->modify('+1 hour'));
        $tokens->save($second);
        $second->revoke(self::now()->modify('+2 hours'));
        $tokens->save($second);
        self::reload();

        $rotated = $tokens->findByTokenHash($first->tokenHash) ?? static::fail('The first token was not stored.');
        $revoked = $tokens->findByTokenHash($second->tokenHash) ?? static::fail('The second token was not stored.');

        static::assertTrue($rotated->isRotated());
        static::assertEquals(self::now()->modify('+1 hour'), $rotated->rotatedAt);
        static::assertFalse($rotated->isRevoked());
        static::assertTrue($revoked->isRevoked());
        static::assertEquals(self::now()->modify('+2 hours'), $revoked->revokedAt);
    }

    /**
     * RFC 6749 §4.1.2, RFC 9700 §4.13.2, decision 0006: what a replay, a reuse and a logout revoke.
     */
    #[Test]
    public function tokensAreFoundByFamilyByCodeAndBySession(): void
    {
        $tokens = self::tokens();
        $alice = self::user();
        $aliceSession = self::session($alice);
        $otherSession = self::session($alice, self::now()->modify('+1 minute'));
        $client = self::client();
        $family = self::family();
        $sibling = self::family();
        $first = self::token(RefreshToken::generate(), $client, $aliceSession, $family, null, self::now()->modify('+1 minute'));
        $second = self::token(RefreshToken::generate(), $client, $aliceSession, $family, null, self::now()->modify('+2 minutes'));
        $third = self::token(RefreshToken::generate(), $client, $otherSession, $sibling, null, self::now()->modify('+3 minutes'));
        $tokens->save($second);
        $tokens->save($first);
        $tokens->save($third);
        self::reload();

        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes($tokens->findByFamily($family->id)));
        static::assertSame([$third->tokenHash], self::hashes($tokens->findByFamily($sibling->id)));
        static::assertSame([], self::hashes($tokens->findByFamily(Uuid::v7())));
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes($tokens->findByAuthorizationCode($family->authorizationCodeHash)));
        static::assertSame([$first->tokenHash, $second->tokenHash], self::hashes($tokens->findBySession($aliceSession->id)));
        static::assertSame([$third->tokenHash], self::hashes($tokens->findBySession($otherSession->id)));
        static::assertSame([], self::hashes($tokens->findBySession(Uuid::v7())));
    }

    /**
     * A token of a client removed from the configuration is not a token: not found, not listed, so that
     * nothing dereferences a client that does not exist.
     */
    #[Test]
    public function aTokenOfAnUnregisteredClientIsNeitherFoundNorListed(): void
    {
        $tokens = self::tokens();
        $session = self::session(self::user());
        $family = self::family();
        $ghost = new Client(self::tenant(), 'ghost', 'Removed client', TokenEndpointAuthMethod::None, null, [new RedirectUri('https://ghost.example/callback')]);
        $orphan = self::token(RefreshToken::generate(), $ghost, $session, $family, null, self::now()->modify('+1 minute'));
        $kept = self::token(RefreshToken::generate(), self::client(), $session, $family, null, self::now()->modify('+2 minutes'));
        $tokens->save($orphan);
        $tokens->save($kept);
        self::reload();

        static::assertNull($tokens->findByTokenHash($orphan->tokenHash));
        static::assertSame([$kept->tokenHash], self::hashes($tokens->findByFamily($family->id)));
        static::assertSame([$kept->tokenHash], self::hashes($tokens->findBySession($session->id)));
    }

    private static function family(): RefreshTokenFamily
    {
        return new RefreshTokenFamily(Uuid::v7(), AuthorizationCode::hash(AuthorizationCode::generate()), self::now(), self::now()->modify('+90 days'));
    }

    private static function token(string $token, Client $client, AuthenticationSession $session, RefreshTokenFamily $family, ?ClaimsRequest $claims, DateTimeImmutable $issuedAt): RefreshToken
    {
        return new RefreshToken(
            RefreshToken::hash($token),
            $family,
            $client,
            $session,
            [new Scope('openid'), new Scope('offline_access')],
            $claims,
            $session->authenticatedAt(),
            $session->methodReferences(),
            $session->authenticationContextClass,
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
