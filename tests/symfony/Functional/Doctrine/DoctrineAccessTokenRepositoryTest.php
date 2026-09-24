<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\OpaqueTokenValue;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokenInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.6, §5.3: a record keyed by the hash of a value it never keeps, found by that value,
 * removed one at a time, by grant and by session.
 */
final class DoctrineAccessTokenRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function anIssuedTokenComesBackWithWhatAResourceNeeds(): void
    {
        // Given
        $session = self::session(self::user());
        $client = self::client();
        $claims = new ClaimsRequest([
            'name' => new ClaimRequest(true),
        ]);
        $code = Tokens::code('the-code', $client, $session, self::now(), ['openid', 'email'], claims: $claims);
        $value = self::tokens()
            ->issue(GrantedAuthorization::fromAuthorizationCode($code), self::now()->modify('+1 minute'), self::now()->modify('+11 minutes'));
        self::reload();

        // When
        $found = self::tokens()->find($value) ?? static::fail('The token was not stored.');

        // Then
        static::assertSame(OpaqueTokenValue::hash($value), $found->tokenHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertTrue($code->grantId->equals($found->grantId));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->registration->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertEquals([new Scope('openid'), new Scope('email')], $found->scopes->all);
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authentication->authenticatedAt);
        static::assertSame(['pwd'], $found->authentication->methods);
        static::assertSame('1', $found->authentication->contextClass);
        static::assertEquals(self::now()->modify('+1 minute'), $found->issuedAt);
        static::assertEquals(self::now()->modify('+11 minutes'), $found->expiresAt);
    }

    #[Test]
    public function aTokenIsFoundByItsValueNeverByItsHash(): void
    {
        // Given
        $value = self::tokens()->issue(self::authorization(self::session(self::user())), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When / Then
        static::assertNotNull(self::tokens()->find($value));
        static::assertNull(self::tokens()->find(OpaqueTokenValue::hash($value)));
        static::assertNull(self::tokens()->find('unknown'));
    }

    #[Test]
    public function aRevokedTokenIsGone(): void
    {
        // Given
        $session = self::session(self::user());
        $revoked = self::tokens()->issue(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        $kept = self::tokens()->issue(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        self::reload();
        $record = self::tokens()->find($revoked) ?? static::fail('The token was not stored.');

        // When
        self::revoker()->revoke($record);
        self::reload();

        // Then
        static::assertNull(self::tokens()->find($revoked));
        static::assertNotNull(self::tokens()->find($kept));
    }

    /**
     * RFC 6749 §4.1.2: the tokens of a grant go together, in issuance order, and are told.
     */
    #[Test]
    public function theTokensOfAGrantAreRevokedTogether(): void
    {
        // Given
        $session = self::session(self::user());
        $code = Tokens::code('the-code', self::client(), $session, self::now());
        $second = self::tokens()
            ->issue(GrantedAuthorization::fromAuthorizationCode($code), self::now()->modify('+2 minutes'), self::now()->modify('+12 minutes'));
        $first = self::tokens()
            ->issue(GrantedAuthorization::fromAuthorizationCode($code), self::now()->modify('+1 minute'), self::now()->modify('+11 minutes'));
        $other = self::tokens()->issue(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When
        $revoked = self::grantRevoker()->revokeByGrant($code->grantId);
        self::reload();

        // Then
        static::assertSame([OpaqueTokenValue::hash($first), OpaqueTokenValue::hash($second)], self::hashes($revoked));
        static::assertNull(self::tokens()->find($first));
        static::assertNull(self::tokens()->find($second));
        static::assertNotNull(self::tokens()->find($other));
        static::assertSame([], self::grantRevoker()->revokeByGrant($code->grantId), 'nothing left');
    }

    /**
     * Architecture §4.9: the tokens of a session go together; those of another session stay.
     */
    #[Test]
    public function theTokensOfASessionAreRevokedTogether(): void
    {
        // Given
        $alice = self::user();
        $session = self::session($alice);
        $otherSession = self::session($alice, self::now()->modify('+1 minute'));
        $here = self::tokens()->issue(self::authorization($session), self::now(), self::now()->modify('+10 minutes'));
        $elsewhere = self::tokens()->issue(self::authorization($otherSession), self::now(), self::now()->modify('+10 minutes'));
        self::reload();

        // When
        $revoked = self::sessionRevoker()->revokeBySession($session->id);
        self::reload();

        // Then
        static::assertSame([OpaqueTokenValue::hash($here)], self::hashes($revoked));
        static::assertNull(self::tokens()->find($here));
        static::assertNotNull(self::tokens()->find($elsewhere));
    }

    /**
     * A token of a client removed from the configuration is not a token: not found, and removed with
     * the others without being told.
     */
    #[Test]
    public function aTokenOfAnUnregisteredClientIsNeitherFoundNorTold(): void
    {
        // Given
        $session = self::session(self::user());
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration('ghost', 'Removed client', Methods::none(), false, [new RedirectUri('https://ghost.example/callback')]),
        );
        $grant = Uuid::v7();
        $orphan = self::tokens()
            ->issue(
                GrantedAuthorization::fromAuthorizationCode(Tokens::code('ghost-code', $ghost, $session, self::now(), grantId: $grant)),
                self::now(),
                self::now()->modify('+10 minutes'),
            );
        $kept = self::tokens()
            ->issue(
                GrantedAuthorization::fromAuthorizationCode(Tokens::code(
                    'the-code',
                    self::client(),
                    $session,
                    self::now()->modify('+1 minute'),
                    grantId: $grant,
                )),
                self::now()->modify('+1 minute'),
                self::now()->modify('+11 minutes'),
            );
        self::reload();

        // When
        $found = self::tokens()->find($orphan);
        $revoked = self::grantRevoker()->revokeByGrant($grant);

        // Then
        static::assertNull($found);
        static::assertSame([OpaqueTokenValue::hash($kept)], self::hashes($revoked));
        static::assertEquals(
            0,
            self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM heidi_access_token'),
            'the row of the ghost went with the others',
        );
    }

    private static function authorization(AuthenticationSession $session): GrantedAuthorization
    {
        return GrantedAuthorization::fromAuthorizationCode(Tokens::code('a-code', self::client(), $session, self::now()));
    }

    private static function tokens(): AccessTokenRepositoryInterface
    {
        return self::service('test.heidi.access_tokens_store', AccessTokenRepositoryInterface::class);
    }

    private static function revoker(): CanRevokeAccessTokenInterface
    {
        return self::service('test.heidi.access_tokens_store', CanRevokeAccessTokenInterface::class);
    }

    private static function grantRevoker(): CanRevokeAccessTokensByGrantInterface
    {
        return self::service('test.heidi.access_tokens_store', CanRevokeAccessTokensByGrantInterface::class);
    }

    private static function sessionRevoker(): CanRevokeAccessTokensBySessionInterface
    {
        return self::service('test.heidi.access_tokens_store', CanRevokeAccessTokensBySessionInterface::class);
    }

    /**
     * @param list<StoredAccessToken> $tokens
     *
     * @return list<string>
     */
    private static function hashes(array $tokens): array
    {
        return array_map(static fn (StoredAccessToken $token): string => $token->tokenHash, $tokens);
    }
}
