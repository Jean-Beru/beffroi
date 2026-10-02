<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateInterval;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\RefreshTokenDue;
use Beffroi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Exception\InvalidAuthorizationDetailsException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;
use Beffroi\Oidc\Tests\Fixture\Shapes;

final class AuthorizationCodeGrantTest extends TestCase
{
    private const string INVALID_GRANT = 'invalid_grant: The authorization code is invalid.';

    private Tenant $tenant;

    private User $alice;

    private Client $client;

    private Client $publicClient;

    private Client $resourceClient;

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
        $this->resourceClient = Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            clientId: 'calendar-client',
            resources: Clients::resources(),
        );
        $this->offlineClient = new Client(
            $this->tenant,
            new ClientRegistration(
                'mobile',
                new ClientPresentation('Mobile application'),
                Methods::none(),
                false,
                [new RedirectUri('https://mobile.example/callback')],
                Shapes::jwt(),
                grantTypes: [Grants::authorizationCode(), Grants::refreshToken()],
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
        static::assertTrue($this->grant->grantType()->equals(Grants::authorizationCode()));
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
        $authorization = $issued->authorization;
        static::assertInstanceOf(UserAuthorizationInterface::class, $authorization);
        static::assertSame($this->client, $authorization->client);
        static::assertSame($this->session, $authorization->session);
        static::assertTrue($authorization->grantType->equals(Grants::authorizationCode()));
        static::assertSame($code->scopes, $authorization->scopes);
        static::assertSame('n-0S6_WzA2Mj', $authorization->nonce);
    }

    /**
     * RFC 8707 §2.2: a request that names no resource takes the resources of the authorization it
     * spends, and the access token is addressed to them.
     */
    #[Test]
    public function aValidExchangeAddressesTheTokensToTheResourcesOfTheCode(): void
    {
        // Given
        $this->code('the-code', $this->resourceClient, ['openid'], resources: ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]));

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->resourceClient), $this->request(), $this->context);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $issued->authorization->audience()->values);
    }

    /**
     * RFC 8707 §2: a request that named no resource asks for nothing beyond the provider itself, and
     * its token is addressed to the client that asked for it.
     */
    #[Test]
    public function aCodeThatNamesNoResourceYieldsATokenAddressedToItsClient(): void
    {
        // Given
        $this->code('the-code', $this->client, ['openid']);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertSame(['oidc-demo'], $issued->authorization->audience()->values);
    }

    /**
     * RFC 8707 §2.2: the access token is issued for the subset of resources the request named.
     */
    #[Test]
    public function aTokenRequestNarrowsTheResourcesOfTheCode(): void
    {
        // Given
        $this->code('the-code', $this->resourceClient, ['openid'], resources: ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]));

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->resourceClient),
            $this->request(resource: Clients::CALENDAR),
            $this->context,
        );

        // Then
        static::assertSame([Clients::CALENDAR], $issued->authorization->audience()->values);
    }

    /**
     * RFC 8707 §2.2: whatever subset the access token was narrowed to, the refresh token beside it is
     * bound to the full original grant.
     */
    #[Test]
    public function theRefreshTokenStaysBoundToEveryResourceOfTheGrant(): void
    {
        // Given
        $this->code('the-code', $this->resourceClient, ['openid'], resources: ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]));

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->resourceClient),
            $this->request(resource: Clients::CALENDAR),
            $this->context,
        );

        // Then
        $refreshToken = $issued->refreshToken ?? static::fail('A confidential client registered for refresh_token gets a refresh token.');
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $refreshToken->token->resources?->values());
    }

    /**
     * RFC 9396 §7: a request that asks for no detail takes the details the code carries, which is what the
     * user agreed to.
     */
    #[Test]
    public function aTokenRequestThatAsksForNoDetailTakesTheDetailsOfTheCode(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details();
        $this->code('the-code', $this->client, ['openid'], authorizationDetails: $details);

        // When
        $issued = $this->grant->grant(new AuthenticatedClient($this->client), $this->request(), $this->context);

        // Then
        static::assertTrue(self::userAuthorization($issued)->authorizationDetails?->equals($details));
    }

    /**
     * RFC 9396 §7: the access token carries the subset of details the request asked for.
     */
    #[Test]
    public function aTokenRequestNarrowsTheDetailsOfTheCode(): void
    {
        // Given
        $this->code('the-code', $this->client, ['openid'], authorizationDetails: new AuthorizationDetails([
            AuthorizationDetailTypes::detail('acct-4711'),
            AuthorizationDetailTypes::detail('acct-0815'),
        ]));

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(authorizationDetails: AuthorizationDetailTypes::parameter('acct-0815')),
            $this->context,
        );

        // Then
        static::assertTrue(self::userAuthorization($issued)->authorizationDetails?->equals(AuthorizationDetailTypes::details('acct-0815')));
    }

    /**
     * RFC 9396 §7: whatever subset the access token was narrowed to, the refresh token beside it is bound
     * to the whole of what the user agreed to.
     */
    #[Test]
    public function theRefreshTokenStaysBoundToEveryDetailOfTheGrant(): void
    {
        // Given
        $granted = new AuthorizationDetails([
            AuthorizationDetailTypes::detail('acct-4711'),
            AuthorizationDetailTypes::detail('acct-0815'),
        ]);
        $this->code('the-code', $this->client, ['openid'], authorizationDetails: $granted);

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(authorizationDetails: AuthorizationDetailTypes::parameter('acct-0815')),
            $this->context,
        );

        // Then
        $refreshToken = $issued->refreshToken ?? static::fail('A confidential client registered for refresh_token gets a refresh token.');
        static::assertTrue($refreshToken->token->authorizationDetails?->equals($granted));
    }

    /**
     * RFC 9396 §7: a token request narrows the details of the authorization it spends and never widens
     * them, whether the authorization carries others or none at all.
     */
    #[Test]
    #[DataProvider('provideDetailsTheCodeDoesNotCarry')]
    public function itRefusesADetailTheCodeDoesNotCarry(?string $granted, string $asked): void
    {
        // Given
        $this->code(
            'the-code',
            $this->client,
            ['openid'],
            authorizationDetails: $granted === null ? null : AuthorizationDetailTypes::details($granted),
        );

        // Then
        $this->expectException(InvalidAuthorizationDetailsException::class);
        $this->expectExceptionMessageIs('invalid_authorization_details: The requested authorization detail is not among the details of this authorization (RFC 9396 section 7).');

        // When
        $this->grant->grant(
            new AuthenticatedClient($this->client),
            $this->request(authorizationDetails: AuthorizationDetailTypes::parameter($asked)),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function provideDetailsTheCodeDoesNotCarry(): iterable
    {
        yield 'another detail' => ['acct-4711', 'acct-0815'];
        yield 'no detail at all' => [null, 'acct-4711'];
    }

    /**
     * RFC 8707 §2.2: a token request narrows the resources of the authorization it spends and never
     * widens them, whether the authorization carries others or none at all.
     *
     * @param list<string>|null $granted
     */
    #[Test]
    #[DataProvider('provideResourcesTheCodeDoesNotCarry')]
    public function itRefusesAResourceTheCodeDoesNotCarry(?array $granted, string $asked): void
    {
        // Given
        $this->code(
            'the-code',
            $this->resourceClient,
            ['openid'],
            resources: $granted === null ? null : ResourceIndicators::of($granted),
        );

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: The requested resource is not among the resources of this authorization (RFC 8707 section 2.2).');

        // When
        $this->grant->grant(new AuthenticatedClient($this->resourceClient), $this->request(resource: $asked), $this->context);
    }

    /**
     * @return iterable<string, array{list<string>|null, string}>
     */
    public static function provideResourcesTheCodeDoesNotCarry(): iterable
    {
        yield 'another resource' => [[Clients::CALENDAR], Clients::CONTACTS];
        yield 'no resource at all' => [null, Clients::CALENDAR];
    }

    /**
     * RFC 8707 §2: the value is an absolute URI without a fragment, at the token endpoint as at the
     * authorization endpoint.
     */
    #[Test]
    public function itRefusesAResourceThatIsNotAnAbsoluteUri(): void
    {
        // Given
        $this->code('the-code', $this->resourceClient, ['openid'], resources: ResourceIndicators::of([Clients::CALENDAR]));

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: The resource parameter is an absolute URI without a fragment component (RFC 8707 section 2).');

        // When
        $this->grant->grant(new AuthenticatedClient($this->resourceClient), $this->request(resource: 'cal.example.com'), $this->context);
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
        static::assertSame($code->codeHash, $refreshToken->token->family->grantingRecordHash);
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
                new ClientPresentation('Code only'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://demo.localhost/login/check')],
                Shapes::jwt(),
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
        $this->grant->grant(new AuthenticatedClient($this->client), RequestParameters::of($parameters), $this->context);
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
        $this->failToGrant($this->client, RequestParameters::of($parameters));

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
        $this->accessTokens->save(Tokens::storedAccessToken('of-the-grant', $this->client, $this->session, $this->clock->now(), $code->grantId));
        $other = Tokens::storedAccessToken('of-another-grant', $this->client, $this->session, $this->clock->now());
        $this->accessTokens->save($other);

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
        $this->grant->grant(new AuthenticatedClient($this->client), RequestParameters::of($parameters), $this->context);
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
        $this->failToGrant($this->client, RequestParameters::of($parameters));

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
        $issued = $this->grant->grant(new AuthenticatedClient($client), RequestParameters::of($parameters), $this->context);

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
     * @param callable(self): RequestParameters $request
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
     * @return iterable<string, array{callable(self): RequestParameters}>
     */
    public static function provideRefusedExchanges(): iterable
    {
        yield 'another redirect URI' => [
            static fn (self $test): RequestParameters => $test->request(redirectUri: 'https://demo.localhost/login/check/'),
        ];
        yield 'wrong verifier' => [
            static fn (self $test): RequestParameters => $test->request(verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl'),
        ];
        yield 'expired code' => [static function (self $test): RequestParameters {
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

    private function grant(
        ?DateInterval $familyLifetime = null,
        bool $refreshTokenWithoutOfflineAccess = true,
        ?ServedGrants $served = null,
    ): AuthorizationCodeGrant {
        $issuer = new TokenIssuer(new FakeAccessTokenIssuer(), $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events);

        return new AuthorizationCodeGrant(
            $this->codes,
            new RefreshTokenRevocation($this->refreshTokens),
            $this->accessTokens,
            $issuer,
            new SymfonyUuidGenerator(),
            $this->clock,
            $this->events,
            new RefreshTokenDue($served ?? Grants::served(), $refreshTokenWithoutOfflineAccess),
            new RequestedAuthorizationDetails(AuthorizationDetailTypes::served()),
            $familyLifetime ?? new DateInterval('P90D'),
        );
    }

    /**
     * @param list<string> $scopes
     */
    private function code(
        string $code,
        Client $client,
        array $scopes = ['openid'],
        ?AuthenticationSession $session = null,
        ?ResourceIndicators $resources = null,
        ?AuthorizationDetails $authorizationDetails = null,
    ): AuthorizationCode {
        $record = Tokens::code(
            $code,
            $client,
            $session ?? $this->session,
            $this->clock->now(),
            $scopes,
            resources: $resources,
            authorizationDetails: $authorizationDetails,
        );
        $this->codes->save($record);

        return $record;
    }

    /**
     * @param string|list<string>|null $resource what the request asks its access token to be addressed to (RFC 8707 §2.2)
     *
     * @return array<string, string|list<string>>
     */
    private function parameters(
        string $code = 'the-code',
        string $redirectUri = 'https://demo.localhost/login/check',
        string $verifier = Tokens::CODE_VERIFIER,
        string|array|null $resource = null,
        ?string $authorizationDetails = null,
    ): array {
        $parameters = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $verifier,
        ];
        if ($resource !== null) {
            $parameters['resource'] = $resource;
        }
        if ($authorizationDetails !== null) {
            $parameters['authorization_details'] = $authorizationDetails;
        }

        return $parameters;
    }

    /**
     * @param string|list<string>|null $resource what the request asks its access token to be addressed to (RFC 8707 §2.2)
     */
    private function request(
        string $code = 'the-code',
        string $redirectUri = 'https://demo.localhost/login/check',
        string $verifier = Tokens::CODE_VERIFIER,
        string|array|null $resource = null,
        ?string $authorizationDetails = null,
    ): RequestParameters {
        return RequestParameters::of($this->parameters($code, $redirectUri, $verifier, $resource, $authorizationDetails));
    }

    private function failToGrant(Client $client, RequestParameters $request): void
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

    /**
     * What a grant of a browser flow yields, which is the only kind of authorization these grants produce
     * and the only kind that carries what a user agreed to (RFC 9396 §2).
     */
    private static function userAuthorization(IssuedTokens $issued): UserAuthorizationInterface
    {
        $authorization = $issued->authorization;
        static::assertInstanceOf(UserAuthorizationInterface::class, $authorization);

        return $authorization;
    }
}
