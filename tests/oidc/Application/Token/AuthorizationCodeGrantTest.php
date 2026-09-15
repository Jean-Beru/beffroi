<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use DateInterval;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;

final class AuthorizationCodeGrantTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private Client $client;

    private Client $publicClient;

    private Client $offlineClient;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private InMemoryAuthorizationCodeRepository $codes;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private FakeIdTokenIssuer $idTokens;

    private RecordingEventDispatcher $events;

    private AuthorizationCodeGrant $grant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->publicClient = Clients::public($this->tenant);
        $this->offlineClient = new Client($this->tenant, 'mobile', 'Mobile application', TokenEndpointAuthMethod::None, null, [new RedirectUri('https://mobile.example/callback')], grantTypes: [GrantType::AuthorizationCode, GrantType::RefreshToken], allowedScopes: [Scope::openid(), new Scope('offline_access')]);
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->context = Fixtures::context($this->clock->now());
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->events = new RecordingEventDispatcher();
        $this->grant = $this->grant();
    }

    #[Test]
    public function itHandlesTheAuthorizationCodeGrantType(): void
    {
        static::assertSame(GrantType::AuthorizationCode, $this->grant->grantType());
    }

    /**
     * RFC 6749 §4.1.3, §4.1.4, RFC 7636 §4.6, OIDC Core §3.1.3.3: a valid exchange yields the access
     * token, the ID token with the nonce of the request, and, for a confidential client registered for
     * the refresh_token grant, a refresh token in a new family descending from the code (architecture
     * §4.5, §9). The code is consumed.
     */
    #[Test]
    public function itExchangesAValidCodeForTokens(): void
    {
        $code = $this->code('the-code', $this->client, ['openid', 'profile']);

        $issued = $this->grant->grant($this->client, $this->request(), $this->context);

        static::assertTrue($code->isUsed());
        static::assertEquals($this->clock->now(), $code->usedAt);
        static::assertSame(2, $this->codes->saves);
        static::assertSame($this->client, $issued->authorization->client);
        static::assertSame($this->session, $issued->authorization->session);
        static::assertSame(GrantType::AuthorizationCode, $issued->authorization->grantType);
        static::assertSame($code->scopes, $issued->authorization->scopes);
        static::assertSame('n-0S6_WzA2Mj', $issued->authorization->nonce);
        static::assertSame('id:oidc-demo:alice-subject:n-0S6_WzA2Mj:' . $this->clock->now()->getTimestamp(), $issued->idToken);
        static::assertSame('at:oidc-demo:alice-subject:' . $this->clock->now()->getTimestamp(), $issued->accessToken->value);

        $refreshToken = $issued->refreshToken ?? static::fail('A confidential client registered for refresh_token gets a refresh token.');
        static::assertSame($code->codeHash, $refreshToken->token->family->authorizationCodeHash);
        static::assertEquals($this->clock->now(), $refreshToken->token->family->startedAt);
        static::assertEquals($this->clock->now()->modify('+90 days'), $refreshToken->token->family->expiresAt);
        static::assertEquals($this->clock->now()->modify('+30 days'), $refreshToken->token->expiresAt);
        static::assertSame($code->scopes, $refreshToken->token->scopes);
        static::assertSame([$refreshToken->token], $this->refreshTokens->all());

        static::assertSame([
            'access_token' => $issued->accessToken->value,
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'refresh_token' => $refreshToken->value,
            'id_token' => $issued->idToken,
            'scope' => 'openid profile',
        ], $issued->toResponse()
            ->parameters());

        static::assertCount(1, $this->events->events);
        $event = $this->events->of(TokensIssued::class)[0];
        static::assertSame($issued->authorization, $event->authorization);
        static::assertSame($refreshToken->token, $event->refreshToken);
        static::assertSame($this->context, $event->context);
    }

    /**
     * Architecture §4.5: a public client gets a refresh token only when it asked for "offline_access"
     * (OIDC Core §11) and is registered for the grant.
     */
    #[Test]
    public function aPublicClientGetsARefreshTokenOnlyWithOfflineAccess(): void
    {
        $this->code('without', $this->offlineClient, ['openid']);
        $this->code('with', $this->offlineClient, ['openid', 'offline_access']);
        $this->code('not-registered', $this->publicClient, ['openid']);

        static::assertNull($this->grant->grant($this->offlineClient, $this->request('without', 'https://mobile.example/callback'), $this->context)->refreshToken);
        static::assertNotNull($this->grant->grant($this->offlineClient, $this->request('with', 'https://mobile.example/callback'), $this->context)->refreshToken);
        static::assertNull($this->grant->grant($this->publicClient, $this->request('not-registered', 'https://spa.example/callback'), $this->context)->refreshToken);
        static::assertCount(1, $this->refreshTokens->all());
    }

    /**
     * Architecture §9: the refresh token without "offline_access" is a choice of the tenant for its
     * confidential clients; turned off, "offline_access" is the only way. A client not registered for
     * refresh_token never gets one.
     */
    #[Test]
    public function aConfidentialClientGetsARefreshTokenWithoutOfflineAccessUnlessTheTenantSaysOtherwise(): void
    {
        $strict = $this->grant(refreshTokenWithoutOfflineAccess: false);
        $codeOnly = new Client($this->tenant, 'code-only', 'Code only', TokenEndpointAuthMethod::ClientSecretBasic, new FakePasswordHasher()->hash(Clients::SECRET), [new RedirectUri('https://demo.localhost/login/check')], allowedScopes: [Scope::openid(), new Scope('offline_access')]);
        $this->code('default', $this->client, ['openid']);
        $this->code('strict-without', $this->client, ['openid']);
        $this->code('code-only', $codeOnly, ['openid', 'offline_access']);

        static::assertNotNull($this->grant->grant($this->client, $this->request('default'), $this->context)->refreshToken);
        static::assertNull($strict->grant($this->client, $this->request('strict-without'), $this->context)->refreshToken);
        static::assertNull($this->grant->grant($codeOnly, $this->request('code-only'), $this->context)->refreshToken);
    }

    /**
     * RFC 6749 §4.1.3, RFC 7636 §4.5: "code", "redirect_uri" and "code_verifier" are required; without
     * them nothing is looked up, so nothing is consumed.
     */
    #[Test]
    public function itRequiresTheCodeTheRedirectUriAndTheCodeVerifier(): void
    {
        $code = $this->code('the-code', $this->client);

        foreach (['code', 'redirect_uri', 'code_verifier'] as $missing) {
            $parameters = $this->parameters();
            unset($parameters[$missing]);
            try {
                $this->grant->grant($this->client, new TokenRequest($parameters), $this->context);
                static::fail($missing . ' is required.');
            } catch (InvalidRequestException $exception) {
                static::assertSame('The ' . $missing . ' parameter is missing.', $exception->errorDescription);
            }
        }
        static::assertFalse($code->isUsed());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 7636 §4.1: code-verifier = 43*128unreserved; anything else is a malformed request, not a
     * grant to try.
     */
    #[Test]
    public function itRefusesAMalformedCodeVerifier(): void
    {
        $code = $this->code('the-code', $this->client);

        foreach ([str_repeat('a', 42), str_repeat('a', 129), str_repeat('a', 42) . '=', str_repeat('a', 42) . ' '] as $verifier) {
            try {
                $this->grant->grant($this->client, $this->request(verifier: $verifier), $this->context);
                static::fail('The verifier should have been refused.');
            } catch (InvalidRequestException $exception) {
                static::assertStringContainsString('code_verifier', $exception->errorDescription);
            }
        }
        static::assertFalse($code->isUsed());
    }

    /**
     * RFC 6749 §5.2: an unknown code is "invalid_grant", with nothing to tell it from any other failure.
     */
    #[Test]
    public function itRefusesAnUnknownCode(): void
    {
        $this->code('the-code', $this->client);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('another-code'), $this->context));
        static::assertSame(1, $this->codes->saves, 'the fixture only: nothing was consumed');
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 6749 §4.1.2: a code presented twice is denied and every token issued from it is revoked,
     * whichever client presents it the second time; the detection is announced.
     */
    #[Test]
    public function itRevokesTheTokensOfAReplayedCode(): void
    {
        $code = $this->code('the-code', $this->client);
        $first = $this->grant->grant($this->client, $this->request(), $this->context);
        $refreshToken = ($first->refreshToken ?? static::fail('A refresh token was issued.'))->token;
        // as if the client had refreshed once and the first token had been swept meanwhile
        $refreshToken->rotate($this->clock->now());
        $refreshToken->revoke($this->clock->now());
        $this->refreshTokens->save($refreshToken);
        $successor = Tokens::refreshToken('successor', $this->client, $this->session, $this->clock->now(), $refreshToken->family);
        $this->refreshTokens->save($successor);
        $this->clock->sleep(5);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request(), $this->context));

        static::assertTrue($successor->isRevoked());
        static::assertEquals($this->clock->now(), $successor->revokedAt);
        static::assertEquals($this->clock->now()->modify('-5 seconds'), $refreshToken->revokedAt, 'already revoked, left as it was');
        static::assertEquals($this->clock->now()->modify('-5 seconds'), $code->usedAt, 'the first use is what is recorded');
        static::assertSame(4, $this->refreshTokens->saves, 'the exchange, the two fixtures, the revocation');
        $replays = $this->events->of(AuthorizationCodeReplayed::class);
        static::assertCount(1, $replays);
        static::assertSame($code, $replays[0]->code);
        static::assertSame($this->client, $replays[0]->presentedBy);
        static::assertSame([$successor], $replays[0]->revoked);
        static::assertEquals($this->clock->now(), $replays[0]->occurredAt);
        static::assertSame($this->tenant, $replays[0]->tenant);
        static::assertSame($this->context, $replays[0]->context);
        static::assertCount(1, $this->events->of(TokensIssued::class));

        $this->clock->sleep(5);
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->publicClient, $this->request(), $this->context));

        $replays = $this->events->of(AuthorizationCodeReplayed::class);
        static::assertCount(2, $replays);
        static::assertSame($this->publicClient, $replays[1]->presentedBy);
        static::assertSame([], $replays[1]->revoked, 'already revoked five seconds ago');
        static::assertEquals($this->clock->now()->modify('-5 seconds'), $successor->revokedAt);
        static::assertSame(4, $this->refreshTokens->saves);
    }

    /**
     * Architecture §4.4: the first presentation consumes the code, valid or not, so that a wrong
     * verifier cannot be corrected on a second try.
     */
    #[Test]
    public function aFailedAttemptConsumesTheCode(): void
    {
        $code = $this->code('the-code', $this->client);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request(verifier: str_repeat('x', 43)), $this->context));

        static::assertTrue($code->isUsed());
        static::assertSame(2, $this->codes->saves, 'the fixture, then the consumption');
        static::assertSame([], $this->events->events);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request(), $this->context));

        $replays = $this->events->of(AuthorizationCodeReplayed::class);
        static::assertCount(1, $replays);
        static::assertSame([], $replays[0]->revoked);
        static::assertSame([], $this->refreshTokens->all());
    }

    /**
     * RFC 6749 §4.1.3: the code was issued to the authenticated client.
     */
    #[Test]
    public function itRefusesACodeIssuedToAnotherClient(): void
    {
        $code = $this->code('the-code', $this->publicClient);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request(redirectUri: 'https://spa.example/callback'), $this->context));

        static::assertTrue($code->isUsed(), 'a code seen by the wrong client is burnt');
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.4: sixty seconds, the last one excluded.
     */
    #[Test]
    public function itRefusesAnExpiredCode(): void
    {
        $this->code('fresh', $this->client);
        $this->code('stale', $this->client);
        $this->clock->sleep(59);

        static::assertNotNull($this->grant->grant($this->client, $this->request('fresh'), $this->context)->idToken);

        $this->clock->sleep(1);
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('stale'), $this->context));
    }

    /**
     * RFC 6749 §4.1.3: "redirect_uri" is identical to the one of the authorization request; a
     * registered URI that is not that one does not do.
     */
    #[Test]
    public function itRefusesAnotherRedirectUri(): void
    {
        $this->code('the-code', $this->client);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request(redirectUri: 'https://demo.localhost/login/check/'), $this->context));
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 7636 §4.6: the verifier must hash to the challenge.
     */
    #[Test]
    public function itRefusesAWrongCodeVerifier(): void
    {
        $this->code('the-code', $this->client);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request(verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl'), $this->context));
        static::assertSame([], $this->events->events);
    }

    /**
     * A code binds a session; a session that ended between the authorization and the exchange, by a
     * logout in another tab for instance, yields no token.
     */
    #[Test]
    public function itRefusesACodeWhoseSessionIsNoLongerActive(): void
    {
        $ended = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->code('ended', $this->client, session: $ended);
        $ended->end(SessionEnd::User, $this->clock->now());
        $expiring = Fixtures::session($this->alice, $this->clock->now()->modify('-12 hours +30 seconds'));
        $this->code('expiring', $this->client, session: $expiring);
        $this->clock->sleep(30);

        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('ended'), $this->context));
        $this->assertInvalidGrant(fn (): IssuedTokens => $this->grant->grant($this->client, $this->request('expiring'), $this->context));
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.6: the lifetime of the family is the tenant's.
     */
    #[Test]
    public function theFamilyLifetimeIsConfigurable(): void
    {
        $this->code('the-code', $this->client);
        $grant = $this->grant(new DateInterval('P7D'));

        $issued = $grant->grant($this->client, $this->request(), $this->context);

        $refreshToken = $issued->refreshToken ?? static::fail('A refresh token was issued.');
        static::assertEquals($this->clock->now()->modify('+7 days'), $refreshToken->token->family->expiresAt);
        static::assertEquals($this->clock->now()->modify('+7 days'), $refreshToken->token->expiresAt, 'capped by the family');
    }

    private function grant(?DateInterval $familyLifetime = null, bool $refreshTokenWithoutOfflineAccess = true): AuthorizationCodeGrant
    {
        $issuer = new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $this->refreshTokens, $this->events);

        return new AuthorizationCodeGrant($this->codes, $this->refreshTokens, $issuer, $this->clock, $this->events, $familyLifetime ?? new DateInterval('P90D'), $refreshTokenWithoutOfflineAccess);
    }

    /**
     * @param list<string> $scopes
     */
    private function code(string $code, Client $client, array $scopes = ['openid'], ?AuthenticationSession $session = null): AuthorizationCode
    {
        $record = Tokens::code($code, $client, $session ?? $this->session, $this->clock->now(), $scopes);
        $this->codes->save($record);

        return $record;
    }

    /**
     * @return array<string, string>
     */
    private function parameters(string $code = 'the-code', string $redirectUri = 'https://demo.localhost/login/check', string $verifier = Tokens::CODE_VERIFIER): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $verifier,
        ];
    }

    private function request(string $code = 'the-code', string $redirectUri = 'https://demo.localhost/login/check', string $verifier = Tokens::CODE_VERIFIER): TokenRequest
    {
        return new TokenRequest($this->parameters($code, $redirectUri, $verifier));
    }

    /**
     * @param callable(): IssuedTokens $attempt
     */
    private function assertInvalidGrant(callable $attempt): void
    {
        try {
            $attempt();
            static::fail('The grant should have failed.');
        } catch (InvalidGrantException $exception) {
            static::assertSame('The authorization code is invalid.', $exception->errorDescription);
            static::assertSame(400, $exception->statusCode);
        }
    }
}
