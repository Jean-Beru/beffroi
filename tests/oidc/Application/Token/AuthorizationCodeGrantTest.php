<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use DateInterval;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\RefreshTokenRevocation;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;

final class AuthorizationCodeGrantTest extends TestCase
{
    private const string INVALID_GRANT = 'invalid_grant: The authorization code is invalid.';

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

    private InMemoryAccessTokenRepository $accessTokens;

    private FakeIdTokenIssuer $idTokens;

    private RecordingEventDispatcher $events;

    private AuthorizationCodeGrant $grant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->publicClient = Clients::public($this->tenant);
        $this->offlineClient = new Client(
            $this->tenant,
            new ClientRegistration(
                'mobile',
                'Mobile application',
                Methods::none(),
                false,
                [new RedirectUri('https://mobile.example/callback')],
                grantTypes: [GrantType::AuthorizationCode, GrantType::RefreshToken],
                allowedScopes: new Scopes([Scope::openid(), new Scope('offline_access')]),
            ),
        );
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->context = Fixtures::context($this->clock->now());
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->accessTokens = new InMemoryAccessTokenRepository();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->events = new RecordingEventDispatcher();
        $this->grant = $this->grant();
    }

    #[Test]
    public function itHandlesTheAuthorizationCodeGrantType(): void
    {
        // When / Then
        static::assertSame(GrantType::AuthorizationCode, $this->grant->grantType());
    }

    /**
     * RFC 6749 §4.1.2: a valid exchange consumes the code.
     */
    #[Test]
    public function aValidExchangeConsumesTheCode(): void
    {
        // Given
        $code = $this->code('the-code', $this->client, ['openid', 'profile']);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertTrue($code->isUsed());
        static::assertEquals($this->clock->now(), $code->usedAt);
        static::assertSame(2, $this->codes->saves);
    }

    /**
     * RFC 6749 §4.1.3, §4.1.4: the tokens are issued for the client, the session and the scopes of the code.
     */
    #[Test]
    public function aValidExchangeYieldsTheAuthorizationOfTheCode(): void
    {
        // Given
        $code = $this->code('the-code', $this->client, ['openid', 'profile']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame($this->client, $issued->authorization->client);
        static::assertSame($this->session, $issued->authorization->session);
        static::assertSame(GrantType::AuthorizationCode, $issued->authorization->grantType);
        static::assertSame($code->scopes, $issued->authorization->scopes);
        static::assertSame('n-0S6_WzA2Mj', $issued->authorization->nonce);
    }

    /**
     * RFC 7636 §4.6, OIDC Core §3.1.3.3: a valid exchange yields the access token and the ID token with
     * the nonce of the request.
     */
    #[Test]
    public function aValidExchangeYieldsTheAccessTokenAndTheIdToken(): void
    {
        // Given
        $this->code('the-code', $this->client, ['openid', 'profile']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame('id:oidc-demo:alice-subject:n-0S6_WzA2Mj:' . $this->clock->now()->getTimestamp(), $issued->idToken);
        static::assertSame('at:oidc-demo:alice-subject:' . $this->clock->now()->getTimestamp(), $issued->accessToken->value);
    }

    /**
     * Architecture §4.5, §9: a confidential client registered for the refresh_token grant gets a refresh
     * token in a new family descending from the code.
     */
    #[Test]
    public function aConfidentialClientGetsARefreshTokenInANewFamilyDescendingFromTheCode(): void
    {
        // Given
        $code = $this->code('the-code', $this->client, ['openid', 'profile']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $refreshToken = $issued->refreshToken ?? static::fail('A confidential client registered for refresh_token gets a refresh token.');
        static::assertSame($code->codeHash, $refreshToken->token->family->authorizationCodeHash);
        static::assertEquals($this->clock->now(), $refreshToken->token->family->startedAt);
        static::assertEquals($this->clock->now()->modify('+90 days'), $refreshToken->token->family->expiresAt);
        static::assertEquals($this->clock->now()->modify('+30 days'), $refreshToken->token->expiresAt);
        static::assertSame($code->scopes, $refreshToken->token->scopes);
        static::assertSame([$refreshToken->token], $this->refreshTokens->all());
    }

    /**
     * RFC 6749 §5.1, OIDC Core §3.1.3.3: the response carries every token issued.
     */
    #[Test]
    public function theResponseCarriesEveryTokenIssued(): void
    {
        // Given
        $this->code('the-code', $this->client, ['openid', 'profile']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame(
            [
                'access_token' => $issued->accessToken->value,
                'token_type' => 'Bearer',
                'expires_in' => 600,
                'refresh_token' => $issued->refreshToken?->value,
                'id_token' => $issued->idToken,
                'scope' => 'openid profile',
            ],
            $issued->toResponse()->parameters(),
        );
    }

    #[Test]
    public function theExchangeIsAnnouncedOnceWithTheRequestContext(): void
    {
        // Given
        $this->code('the-code', $this->client, ['openid', 'profile']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertCount(1, $this->events->events);
        $event = $this->events->of(TokensIssued::class)[0];
        static::assertSame($issued->authorization->grantId, $event->grantId);
        static::assertSame($issued->refreshToken?->token->tokenHash, $event->refreshTokenHash);
        static::assertSame($this->context, $event->context);
    }

    /**
     * Architecture §4.5: a public client gets no refresh token without "offline_access" (OIDC Core §11).
     */
    #[Test]
    public function aPublicClientGetsNoRefreshTokenWithoutOfflineAccess(): void
    {
        // Given
        $this->code('the-code', $this->offlineClient, ['openid']);

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->offlineClient),
            $this->request(redirectUri: 'https://mobile.example/callback'),
            $this->context,
        );

        // Then
        static::assertNull($issued->refreshToken);
        static::assertSame([], $this->refreshTokens->all());
    }

    /**
     * Architecture §4.5: a public client registered for the grant gets a refresh token with "offline_access".
     */
    #[Test]
    public function aPublicClientGetsARefreshTokenWithOfflineAccess(): void
    {
        // Given
        $this->code('the-code', $this->offlineClient, ['openid', 'offline_access']);

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->offlineClient),
            $this->request(redirectUri: 'https://mobile.example/callback'),
            $this->context,
        );

        // Then
        static::assertNotNull($issued->refreshToken);
        static::assertCount(1, $this->refreshTokens->all());
    }

    /**
     * Architecture §4.5: a public client not registered for the grant never gets a refresh token.
     */
    #[Test]
    public function aPublicClientNotRegisteredForTheGrantGetsNoRefreshToken(): void
    {
        // Given
        $this->code('the-code', $this->publicClient, ['openid']);

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->publicClient),
            $this->request(redirectUri: 'https://spa.example/callback'),
            $this->context,
        );

        // Then
        static::assertNull($issued->refreshToken);
    }

    /**
     * Architecture §9: the refresh token without "offline_access" is a choice of the tenant for its
     * confidential clients, on by default.
     */
    #[Test]
    public function aConfidentialClientGetsARefreshTokenWithoutOfflineAccessByDefault(): void
    {
        // Given
        $this->code('the-code', $this->client, ['openid']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertNotNull($issued->refreshToken);
    }

    /**
     * Architecture §9: turned off, "offline_access" is the only way.
     */
    #[Test]
    public function aConfidentialClientGetsNoRefreshTokenWithoutOfflineAccessWhenTheTenantSaysSo(): void
    {
        // Given
        $strict = $this->grant(refreshTokenWithoutOfflineAccess: false);
        $this->code('the-code', $this->client, ['openid']);

        // When
        $issued = $strict->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertNull($issued->refreshToken);
    }

    /**
     * A client not registered for refresh_token never gets one, offline_access or not.
     */
    #[Test]
    public function aClientNotRegisteredForTheGrantGetsNoRefreshTokenEvenWithOfflineAccess(): void
    {
        // Given
        $codeOnly = new Client(
            $this->tenant,
            new ClientRegistration(
                'code-only',
                'Code only',
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://demo.localhost/login/check')],
                allowedScopes: new Scopes([Scope::openid(), new Scope('offline_access')]),
            ),
            new HashedClientSecret(new FakePasswordHasher()->hash(Clients::SECRET)),
        );
        $this->code('the-code', $codeOnly, ['openid', 'offline_access']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($codeOnly), $this->request(), $this->context);

        // Then
        static::assertNull($issued->refreshToken);
    }

    /**
     * RFC 6749 §4.1.3: "code" and "redirect_uri" are required. Whether "code_verifier" is depends on the
     * code (RFC 7636 §4.5, RFC 9700 §4.8.2), so it is judged once the code is found.
     */
    #[Test]
    #[DataProvider('provideRequiredParameters')]
    public function itRequiresTheCodeAndTheRedirectUri(string $missing): void
    {
        // Given
        $this->code('the-code', $this->client);
        $parameters = $this->parameters();
        unset($parameters[$missing]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The ' . $missing . ' parameter is missing.');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), new TokenRequest($parameters), $this->context);
    }

    /**
     * Without a required parameter nothing is looked up, so nothing is consumed.
     */
    #[Test]
    #[DataProvider('provideRequiredParameters')]
    public function aRequestWithoutARequiredParameterConsumesNothing(string $missing): void
    {
        // Given
        $code = $this->code('the-code', $this->client);
        $parameters = $this->parameters();
        unset($parameters[$missing]);

        // When
        $this->failToGrant($this->client, new TokenRequest($parameters));

        // Then
        static::assertFalse($code->isUsed());
        static::assertSame([], $this->events->events);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRequiredParameters(): iterable
    {
        yield 'code' => ['code'];
        yield 'redirect_uri' => ['redirect_uri'];
    }

    /**
     * RFC 7636 §4.1: code-verifier = 43*128unreserved; anything else is a malformed request, not a
     * grant to try.
     */
    #[Test]
    #[DataProvider('provideMalformedVerifiers')]
    public function itRefusesAMalformedCodeVerifier(string $verifier): void
    {
        // Given
        $this->code('the-code', $this->client);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('code_verifier');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(verifier: $verifier), $this->context);
    }

    #[Test]
    #[DataProvider('provideMalformedVerifiers')]
    public function aMalformedCodeVerifierConsumesNothing(string $verifier): void
    {
        // Given
        $code = $this->code('the-code', $this->client);

        // When
        $this->failToGrant($this->client, $this->request(verifier: $verifier));

        // Then
        static::assertFalse($code->isUsed());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedVerifiers(): iterable
    {
        yield 'too short' => [str_repeat('a', 42)];
        yield 'too long' => [str_repeat('a', 129)];
        yield 'base64 padding' => [str_repeat('a', 42) . '='];
        yield 'space' => [str_repeat('a', 42) . ' '];
    }

    /**
     * RFC 6749 §5.2: an unknown code is "invalid_grant", with nothing to tell it from any other failure.
     */
    #[Test]
    public function itRefusesAnUnknownCode(): void
    {
        // Given
        $this->code('the-code', $this->client);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request('another-code'), $this->context);
    }

    #[Test]
    public function anUnknownCodeConsumesNothing(): void
    {
        // Given
        $this->code('the-code', $this->client);

        // When
        $this->failToGrant($this->client, $this->request('another-code'));

        // Then
        static::assertSame(1, $this->codes->saves, 'the fixture only: nothing was consumed');
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 6749 §4.1.2: a code presented twice is denied.
     */
    #[Test]
    public function itRefusesAReplayedCode(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    /**
     * RFC 6749 §4.1.2: every token issued from a replayed code is revoked, the successors of a rotation
     * included; one already revoked keeps its date.
     */
    #[Test]
    public function aReplayedCodeRevokesTheTokensIssuedFromIt(): void
    {
        // Given
        $code = $this->code('the-code', $this->client);
        $first = $this->firstExchangeThenARotation();
        $successor = $this->successorOf($first);
        $this->clock->sleep(5);

        // When
        $this->failToGrant($this->client, $this->request());

        // Then
        static::assertTrue($successor->isRevoked());
        static::assertEquals($this->clock->now(), $successor->revokedAt);
        static::assertEquals($this->clock->now()->modify('-5 seconds'), $first->revokedAt, 'already revoked, left as it was');
        static::assertEquals($this->clock->now()->modify('-5 seconds'), $code->usedAt, 'the first use is what is recorded');
        static::assertSame(4, $this->refreshTokens->saves, 'the exchange, the two fixtures, the revocation');
    }

    /**
     * RFC 6749 §4.1.2: the stored access tokens of the grant go with it; one of another grant stays.
     */
    #[Test]
    public function aReplayedCodeRevokesTheStoredAccessTokensOfItsGrant(): void
    {
        // Given
        $code = $this->code('the-code', $this->client);
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        $this->accessTokens->keep(Tokens::storedAccessToken('of-the-grant', $this->client, $this->session, $this->clock->now(), $code->grantId));
        $other = Tokens::storedAccessToken('of-another-grant', $this->client, $this->session, $this->clock->now());
        $this->accessTokens->keep($other);

        // When
        $this->failToGrant($this->client, $this->request());

        // Then
        static::assertSame([$other], $this->accessTokens->all());
    }

    /**
     * RFC 6749 §4.1.2: the grant itself is revoked, which is what the provider's own UserInfo reads to
     * refuse the access tokens issued from the code; a third presentation keeps the first date.
     */
    #[Test]
    public function aReplayedCodeRevokesTheGrant(): void
    {
        // Given
        $code = $this->code('the-code', $this->client);
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        $this->clock->sleep(5);

        // When
        $this->failToGrant($this->client, $this->request());
        $this->clock->sleep(5);
        $this->failToGrant($this->client, $this->request());

        // Then
        static::assertTrue($code->isRevoked());
        static::assertEquals($this->clock->now()->modify('-5 seconds'), $code->revokedAt);
    }

    /**
     * The detection is announced, whichever client presents the code the second time.
     */
    #[Test]
    public function aReplayIsAnnouncedWithWhatWasRevoked(): void
    {
        // Given
        $code = $this->code('the-code', $this->client);
        $successor = $this->successorOf($this->firstExchangeThenARotation());
        $this->clock->sleep(5);

        // When
        $this->failToGrant($this->client, $this->request());

        // Then
        $replays = $this->events->of(AuthorizationCodeReplayed::class);
        static::assertCount(1, $replays);
        static::assertSame($code->codeHash, $replays[0]->codeHash);
        static::assertSame($this->client->registration->clientId, $replays[0]->presentedBy);
        static::assertSame([$successor->tokenHash], $replays[0]->revokedTokenHashes);
        static::assertEquals($this->clock->now(), $replays[0]->occurredAt);
        static::assertSame($this->tenant, $replays[0]->tenant);
        static::assertSame($this->context, $replays[0]->context);
        static::assertCount(1, $this->events->of(TokensIssued::class));
    }

    #[Test]
    public function aSecondReplayByAnotherClientIsAnnouncedWithNothingLeftToRevoke(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $successor = $this->successorOf($this->firstExchangeThenARotation());
        $this->clock->sleep(5);
        $this->failToGrant($this->client, $this->request());
        $this->clock->sleep(5);

        // When
        $this->failToGrant($this->publicClient, $this->request());

        // Then
        $replays = $this->events->of(AuthorizationCodeReplayed::class);
        static::assertCount(2, $replays);
        static::assertSame($this->publicClient->registration->clientId, $replays[1]->presentedBy);
        static::assertSame([], $replays[1]->revokedTokenHashes, 'already revoked five seconds ago');
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
        // Given
        $code = $this->code('the-code', $this->client);

        // When
        $this->failToGrant($this->client, $this->request(verifier: str_repeat('x', 43)));

        // Then
        static::assertTrue($code->isUsed());
        static::assertSame(2, $this->codes->saves, 'the fixture, then the consumption');
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aSecondTryAfterAFailedAttemptIsAReplayWithNothingToRevoke(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $this->failToGrant($this->client, $this->request(verifier: str_repeat('x', 43)));

        // When
        $this->failToGrant($this->client, $this->request());

        // Then
        $replays = $this->events->of(AuthorizationCodeReplayed::class);
        static::assertCount(1, $replays);
        static::assertSame([], $replays[0]->revokedTokenHashes);
        static::assertSame([], $this->refreshTokens->all());
    }

    /**
     * RFC 6749 §4.1.3: the code was issued to the authenticated client.
     */
    #[Test]
    public function itRefusesACodeIssuedToAnotherClient(): void
    {
        // Given
        $this->code('the-code', $this->publicClient);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(redirectUri: 'https://spa.example/callback'), $this->context);
    }

    #[Test]
    public function aCodeSeenByTheWrongClientIsBurnt(): void
    {
        // Given
        $code = $this->code('the-code', $this->publicClient);

        // When
        $this->failToGrant($this->client, $this->request(redirectUri: 'https://spa.example/callback'));

        // Then
        static::assertTrue($code->isUsed());
    }

    /**
     * Architecture §4.4: sixty seconds, the last one included.
     */
    #[Test]
    public function itExchangesACodeUntilItsLastSecond(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $this->clock->sleep(59);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertNotNull($issued->idToken);
    }

    /**
     * Architecture §4.4: sixty seconds, the sixtieth excluded.
     */
    #[Test]
    public function itRefusesAnExpiredCode(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $this->clock->sleep(60);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    /**
     * RFC 6749 §4.1.3: "redirect_uri" is identical to the one of the authorization request; a
     * registered URI that is not that one does not do.
     */
    #[Test]
    public function itRefusesAnotherRedirectUri(): void
    {
        // Given
        $this->code('the-code', $this->client);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(redirectUri: 'https://demo.localhost/login/check/'), $this->context);
    }

    /**
     * RFC 7636 §4.5, §4.6: a code issued with a challenge is exchanged with the verifier, whatever the
     * client is registered with.
     */
    #[Test]
    public function itRefusesACodeIssuedWithAChallengeWithoutACodeVerifier(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $parameters = $this->parameters();
        unset($parameters['code_verifier']);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), new TokenRequest($parameters), $this->context);
    }

    /**
     * The code was looked up, so it is consumed: a verifier cannot be tried after a first attempt without one.
     */
    #[Test]
    public function aCodeIssuedWithAChallengePresentedWithoutAVerifierIsConsumed(): void
    {
        // Given
        $code = $this->code('the-code', $this->client);
        $parameters = $this->parameters();
        unset($parameters['code_verifier']);

        // When
        $this->failToGrant($this->client, new TokenRequest($parameters));

        // Then
        static::assertTrue($code->isUsed());
    }

    /**
     * Decision 0008: a client registered without the PKCE requirement gets a code without a challenge
     * when it sent none, and exchanges it without a verifier.
     */
    #[Test]
    public function aCodeIssuedWithoutAChallengeIsExchangedWithoutAVerifier(): void
    {
        // Given
        $client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), clientId: 'legacy', requiresPkce: false);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), pkce: false));
        $parameters = $this->parameters();
        unset($parameters['code_verifier']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($client), new TokenRequest($parameters), $this->context);

        // Then
        static::assertSame('at:legacy:alice-subject:' . $this->clock->now()->getTimestamp(), $issued->accessToken->value);
    }

    /**
     * RFC 9700 §4.8.2: a code_verifier is accepted only if a code_challenge was present in the
     * authorization request; otherwise an attacker who stripped the challenge would be exchanging a
     * code the client never bound.
     */
    #[Test]
    public function itRefusesACodeVerifierForACodeIssuedWithoutAChallenge(): void
    {
        // Given
        $client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), clientId: 'legacy', requiresPkce: false);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), pkce: false));

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($client), $this->request(), $this->context);
    }

    /**
     * RFC 7636 §4.6: the verifier must hash to the challenge.
     */
    #[Test]
    public function itRefusesAWrongCodeVerifier(): void
    {
        // Given
        $this->code('the-code', $this->client);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl'), $this->context);
    }

    /**
     * A code binds a session; a session that ended between the authorization and the exchange, by a
     * logout in another tab for instance, yields no token.
     */
    #[Test]
    public function itRefusesACodeWhoseSessionEnded(): void
    {
        // Given
        $ended = Fixtures::session($this->alice, $this->clock->now()->modify('-1 hour'));
        $this->code('the-code', $this->client, session: $ended);
        $ended->end(SessionEnd::User, $this->clock->now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    #[Test]
    public function itRefusesACodeWhoseSessionExpired(): void
    {
        // Given
        $expiring = Fixtures::session($this->alice, $this->clock->now()->modify('-12 hours +30 seconds'));
        $this->code('the-code', $this->client, session: $expiring);
        $this->clock->sleep(30);

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs(self::INVALID_GRANT);

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
    }

    /**
     * A refused exchange issues nothing and announces nothing.
     *
     * @param callable(self): TokenRequest $request
     */
    #[Test]
    #[DataProvider('provideRefusedExchanges')]
    public function aRefusedExchangeAnnouncesNothing(callable $request): void
    {
        // Given
        $this->code('the-code', $this->client);

        // When
        $this->failToGrant($this->client, $request($this));

        // Then
        static::assertSame([], $this->events->events);
        static::assertSame([], $this->refreshTokens->all());
    }

    /**
     * @return iterable<string, array{callable(self): TokenRequest}>
     */
    public static function provideRefusedExchanges(): iterable
    {
        yield 'another redirect URI' => [
            static fn (self $test): TokenRequest => $test->request(redirectUri: 'https://demo.localhost/login/check/'),
        ];
        yield 'wrong verifier' => [
            static fn (self $test): TokenRequest => $test->request(verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl'),
        ];
        yield 'expired code' => [static function (self $test): TokenRequest {
            $test->clock->sleep(60);

            return $test->request();
        }];
    }

    /**
     * Architecture §4.6: the lifetime of the family is the tenant's, and caps the token.
     */
    #[Test]
    public function theFamilyLifetimeIsConfigurable(): void
    {
        // Given
        $this->code('the-code', $this->client);
        $grant = $this->grant(new DateInterval('P7D'));

        // When
        $issued = $grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        $refreshToken = $issued->refreshToken ?? static::fail('A refresh token was issued.');
        static::assertEquals($this->clock->now()->modify('+7 days'), $refreshToken->token->family->expiresAt);
        static::assertEquals($this->clock->now()->modify('+7 days'), $refreshToken->token->expiresAt, 'capped by the family');
    }

    private function grant(?DateInterval $familyLifetime = null, bool $refreshTokenWithoutOfflineAccess = true): AuthorizationCodeGrant
    {
        $issuer = new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $this->refreshTokens, $this->events);

        return new AuthorizationCodeGrant(
            $this->codes,
            new RefreshTokenRevocation($this->refreshTokens),
            $this->accessTokens,
            $issuer,
            $this->clock,
            $this->events,
            $familyLifetime ?? new DateInterval('P90D'),
            $refreshTokenWithoutOfflineAccess,
        );
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
    private function parameters(
        string $code = 'the-code',
        string $redirectUri = 'https://demo.localhost/login/check',
        string $verifier = Tokens::CODE_VERIFIER,
    ): array {
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $verifier,
        ];
    }

    private function request(
        string $code = 'the-code',
        string $redirectUri = 'https://demo.localhost/login/check',
        string $verifier = Tokens::CODE_VERIFIER,
    ): TokenRequest {
        return new TokenRequest($this->parameters($code, $redirectUri, $verifier));
    }

    private function failToGrant(Client $client, TokenRequest $request): void
    {
        try {
            $this->grant->grant(new AuthenticatedClient($client), $request, $this->context);
            static::fail('The grant should have failed.');
        } catch (InvalidGrantException|InvalidRequestException) {
        }
    }

    /**
     * The first exchange of "the-code", then the refresh token rotated and swept meanwhile, as if the
     * client had refreshed once.
     */
    private function firstExchangeThenARotation(): RefreshToken
    {
        $first = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);
        $refreshToken = ($first->refreshToken ?? static::fail('A refresh token was issued.'))->token;
        $refreshToken->rotate($this->clock->now());
        $refreshToken->revoke($this->clock->now());
        $this->refreshTokens->save($refreshToken);

        return $refreshToken;
    }

    private function successorOf(RefreshToken $rotated): RefreshToken
    {
        $successor = Tokens::refreshToken('successor', $this->client, $this->session, $this->clock->now(), $rotated->family);
        $this->refreshTokens->save($successor);

        return $successor;
    }
}
