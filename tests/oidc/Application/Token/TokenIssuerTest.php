<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use DateInterval;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class TokenIssuerTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private RequestContext $context;

    private FakeAccessTokenIssuer $accessTokens;

    private FakeIdTokenIssuer $idTokens;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private TokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->context = Fixtures::context();
        $this->accessTokens = new FakeAccessTokenIssuer();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer($this->accessTokens, $this->idTokens, $this->refreshTokens, $this->events);
    }

    /**
     * OIDC Core §3.1.3.3: an access token and an ID token; the ID token is minted with the access token
     * of the same response, for at_hash. The refresh token given goes into the response and the event
     * names its record.
     */
    #[Test]
    public function itMintsAnAccessTokenAndAnIdTokenWhenOpenidIsRequested(): void
    {
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile']));
        $family = Tokens::family(Fixtures::now());
        $refreshToken = $this->issuer->refreshToken($family, $authorization, Fixtures::now());

        $issued = $this->issuer->issue($authorization, $refreshToken, $this->context, Fixtures::now());

        static::assertSame($authorization, $issued->authorization);
        static::assertSame('at:spa:alice-subject:' . Fixtures::now()->getTimestamp(), $issued->accessToken->value);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $issued->accessToken->expiresAt);
        static::assertSame('id:spa:alice-subject:n-0S6_WzA2Mj:' . Fixtures::now()->getTimestamp(), $issued->idToken);
        static::assertSame($refreshToken, $issued->refreshToken);
        static::assertSame([$authorization], $this->accessTokens->issued);
        static::assertSame([[$authorization, $issued->accessToken]], $this->idTokens->issued);

        $events = $this->events->of(TokensIssued::class);
        static::assertCount(1, $events);
        static::assertCount(1, $this->events->events);
        static::assertEquals(Fixtures::now(), $events[0]->occurredAt);
        static::assertSame($this->session->tenant, $events[0]->tenant);
        static::assertSame($this->context, $events[0]->context);
        static::assertSame($authorization, $events[0]->authorization);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $events[0]->accessTokenExpiresAt);
        static::assertTrue($events[0]->idTokenIssued);
        static::assertSame($refreshToken->token, $events[0]->refreshToken);
    }

    /**
     * RFC 6749 §6 with a scope narrowed below "openid": an access token only.
     */
    #[Test]
    public function itMintsNoIdTokenWithoutOpenidAndNoRefreshTokenWithoutAFamily(): void
    {
        $token = Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']);
        $authorization = GrantedAuthorization::fromRefreshToken($token, [new Scope('profile')]);

        $issued = $this->issuer->issue($authorization, null, $this->context, Fixtures::now());

        static::assertNull($issued->idToken);
        static::assertNull($issued->refreshToken);
        static::assertSame([], $this->idTokens->issued);
        static::assertSame([], $this->refreshTokens->all());
        static::assertSame(0, $this->refreshTokens->saves);
        $events = $this->events->of(TokensIssued::class);
        static::assertCount(1, $events);
        static::assertFalse($events[0]->idTokenIssued);
        static::assertNull($events[0]->refreshToken);
    }

    /**
     * Architecture §4.6: the refresh token is stored as its hash, for the granted scopes, thirty days
     * sliding within the family; the value goes to the client only.
     */
    #[Test]
    public function itIssuesARefreshTokenStoredHashedInTheFamilyGiven(): void
    {
        $token = Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']);
        $authorization = GrantedAuthorization::fromRefreshToken($token, [new Scope('profile')]);
        $now = Fixtures::now()->modify('+1 day');

        $issued = $this->issuer->refreshToken($token->family, $authorization, $now);

        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $issued->value));
        static::assertSame(RefreshToken::hash($issued->value), $issued->token->tokenHash);
        static::assertSame($token->family, $issued->token->family);
        static::assertSame($this->client, $issued->token->client);
        static::assertSame($this->session, $issued->token->session);
        static::assertSame($token->scopes, $issued->token->scopes, 'the granted scopes, not the narrowed ones');
        static::assertEquals($now, $issued->token->issuedAt);
        static::assertEquals($now->modify('+30 days'), $issued->token->expiresAt);
        static::assertEquals($token->authenticatedAt, $issued->token->authenticatedAt);
        static::assertSame($token->authenticationMethods, $issued->token->authenticationMethods);
        static::assertSame([$issued->token], $this->refreshTokens->all());
        static::assertSame($issued->token, $this->refreshTokens->findByTokenHash(RefreshToken::hash($issued->value)));
        static::assertSame([], $this->events->events, 'the refresh token is announced with the response, by issue()');

        $late = Fixtures::now()->modify('+85 days');
        static::assertEquals($token->family->expiresAt, $this->issuer->refreshToken($token->family, $authorization, $late)->token->expiresAt);

        $shortLived = new TokenIssuer($this->accessTokens, $this->idTokens, $this->refreshTokens, $this->events, new DateInterval('PT1H'));
        static::assertEquals($now->modify('+1 hour'), $shortLived->refreshToken($token->family, $authorization, $now)->token->expiresAt);
    }
}
