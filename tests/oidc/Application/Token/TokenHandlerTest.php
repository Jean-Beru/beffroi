<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Oidc\Tests\Fixture\Secrets;
use function base64_encode;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Token\AuthorizationCodeGrant;
use Heidi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Heidi\Oidc\Application\Token\RefreshTokenDue;
use Heidi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Heidi\Oidc\Application\Token\RefreshTokenGrant;
use Heidi\Oidc\Application\Token\RefreshTokenRevocation;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Application\Token\TokenHandler;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\RefreshTokenRotated;
use Heidi\Oidc\Domain\Event\TokensIssued;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Heidi\Oidc\Exception\AuthorizationPendingException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidDpopProofException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use Heidi\Oidc\Tests\Fixture\Certificates;
use Heidi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Proofs;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Core\JWK;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class TokenHandlerTest extends TestCase
{
    private const string AUTH_REQUEST_ID = 'the-auth-req-id';

    private Tenant $tenant;

    private Client $basicClient;

    private Client $postClient;

    private Client $publicClient;

    private Client $boundClient;

    private AuthenticationSession $session;

    private RequestContext $context;

    private MockClock $clock;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private InMemoryAuthorizationCodeRepository $codes;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private InMemoryBackchannelAuthenticationRecordRepository $backchannelRecords;

    private TokenIssuer $issuer;

    private AuthorizationCodeGrant $codeGrant;

    private TokenHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $alice = Fixtures::user($this->tenant);
        $this->hasher = new FakePasswordHasher();
        $this->basicClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretBasic(), 'basic-client');
        $this->postClient = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'post-client');
        $this->publicClient = Clients::public($this->tenant, 'public-client');
        $this->boundClient = Clients::boundToItsCertificate($this->tenant);
        $this->clients = new InMemoryClientRepository();
        foreach ([$this->basicClient, $this->postClient, $this->publicClient, $this->boundClient] as $client) {
            $this->clients->save($client);
        }
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->session = Fixtures::session($alice, $this->clock->now()->modify('-1 hour'));
        $this->context = Fixtures::context($this->clock->now());
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->backchannelRecords = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer(new FakeAccessTokenIssuer(), new FakeIdTokenIssuer(), $this->refreshTokens, Secrets::drawer(), $this->events);
        $this->codeGrant = new AuthorizationCodeGrant(
            $this->codes,
            new RefreshTokenRevocation($this->refreshTokens),
            new InMemoryAccessTokenRepository(),
            $this->issuer,
            new SymfonyUuidGenerator(),
            $this->clock,
            $this->events,
            new RefreshTokenDue(Grants::served()),
            new RequestedAuthorizationDetails(AuthorizationDetailTypes::served()),
        );
        $refreshGrant = new RefreshTokenGrant(
            $this->refreshTokens,
            new RefreshTokenRevocation($this->refreshTokens),
            $this->issuer,
            new RequestedAuthorizationDetails(AuthorizationDetailTypes::served()),
            $this->clock,
            $this->events,
        );
        $this->handler = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([$this->codeGrant, $refreshGrant]));
    }

    /**
     * RFC 6749 §4.1.3 and §5.1 end to end, the way oidc_login sends it: client_secret_basic with the
     * client_id repeated in the body.
     */
    #[Test]
    public function itExchangesACodeForTokens(): void
    {
        // Given
        $this->codes->save(Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now(), ['openid', 'profile']));

        // When
        $response = $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $this->codeExchange(), $this->context);

        // Then
        $parameters = $response->parameters();
        static::assertSame('at:basic-client:alice-subject:' . $this->clock->now()->getTimestamp(), $parameters['access_token']);
        static::assertSame('Bearer', $parameters['token_type']);
        static::assertSame(600, $parameters['expires_in']);
        static::assertSame('id:basic-client:alice-subject:n-0S6_WzA2Mj:' . $this->clock->now()->getTimestamp(), $parameters['id_token']);
        static::assertSame('openid profile', $parameters['scope']);
        static::assertArrayHasKey('refresh_token', $parameters);
    }

    #[Test]
    public function anExchangeConsumesTheCodeAndRecordsTheRefreshToken(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now(), ['openid', 'profile']);
        $this->codes->save($code);

        // When
        $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $this->codeExchange(), $this->context);

        // Then
        static::assertTrue($code->isUsed());
        static::assertCount(1, $this->refreshTokens->all());
        static::assertCount(1, $this->events->of(TokensIssued::class));
    }

    /**
     * RFC 6749 §6 end to end with client_secret_post.
     */
    #[Test]
    public function itRefreshesTokens(): void
    {
        // Given
        $token = Tokens::refreshToken('the-token', $this->postClient, $this->session, $this->clock->now(), null, ['openid', 'profile']);
        $this->refreshTokens->save($token);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            null,
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'the-token',
                'client_id' => 'post-client',
                'client_secret' => Clients::SECRET,
            ],
            $this->context,
        );

        // Then
        $parameters = $response->parameters();
        static::assertSame('id:post-client:alice-subject:-:' . $this->clock->now()->getTimestamp(), $parameters['id_token']);
        // RFC 6749 §6, FAPI 2.0 Security Profile §5.3.2.1-9: the client authenticated, which is what
        // tells its refresh token from a copy of itself, so the token stands and no new one is handed
        // out; the client keeps the one it has.
        static::assertArrayNotHasKey('refresh_token', $parameters);
        static::assertFalse($token->isRotated());
        static::assertCount(0, $this->events->of(RefreshTokenRotated::class));
    }

    /**
     * RFC 6749 §3.2.1: the client is authenticated before anything else is read, so that a caller that
     * is not a client learns nothing about the request.
     */
    #[Test]
    public function itAuthenticatesTheClientBeforeReadingTheGrant(): void
    {
        // Given
        $this->codes->save(Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now()));

        // When
        try {
            $this->handler->handle(
                $this->tenant,
                self::basic('basic-client', 'wrong-secret'),
                [
                    'code' => 'the-code',
                ],
                $this->context,
            );
            static::fail('The client should have been refused.');
        } catch (InvalidClientException $exception) {
            // Then
            static::assertSame(401, $exception->statusCode);
            static::assertSame('Basic realm="https://id.acme.example"', $exception->challenge);
        }
    }

    /**
     * A refused client consumes nothing and the failure is announced.
     */
    #[Test]
    public function aRefusedClientConsumesNothingAndTheFailureIsAnnounced(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->basicClient, $this->session, $this->clock->now());
        $this->codes->save($code);

        // When
        try {
            $this->handler->handle(
                $this->tenant,
                self::basic('basic-client', 'wrong-secret'),
                [
                    'code' => 'the-code',
                ],
                $this->context,
            );
        } catch (InvalidClientException) {
        }

        // Then
        static::assertFalse($code->isUsed());
        static::assertCount(1, $this->events->of(ClientAuthenticationFailed::class));
        static::assertCount(1, $this->events->events);
    }

    /**
     * RFC 6749 §4.1.3, §6: "grant_type" is required.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideRequestsWithoutGrantType')]
    public function itRequiresAGrantType(array $parameters): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIsOrContains('grant_type');

        // When
        $this->handler->handle($this->tenant, self::basic('basic-client', Clients::SECRET), $parameters, $this->context);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideRequestsWithoutGrantType(): iterable
    {
        yield 'absent' => [[]];
        yield 'empty' => [[
            'grant_type' => '',
        ]];
        yield 'repeated' => [[
            'grant_type' => ['authorization_code'],
        ]];
    }

    /**
     * RFC 6749 §5.2 "unsupported_grant_type": the grants of decision 0006 only.
     */
    #[Test]
    #[DataProvider('provideGrantTypesNotServed')]
    public function itRefusesAGrantTypeTheProviderDoesNotServe(string $grantType): void
    {
        // Then
        $this->expectException(UnsupportedGrantTypeException::class);

        // When
        $this->handler->handle(
            $this->tenant,
            self::basic('basic-client', Clients::SECRET),
            [
                'grant_type' => $grantType,
            ],
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideGrantTypesNotServed(): iterable
    {
        yield 'password' => ['password'];
        yield 'client_credentials' => ['client_credentials'];
        yield 'implicit' => ['implicit'];
        yield 'device_code' => ['urn:ietf:params:oauth:grant-type:device_code'];
        yield 'authorization_code in another case' => ['Authorization_Code'];
    }

    /**
     * RFC 6749 §5.2 "unsupported_grant_type": only the grants the handler was given.
     */
    #[Test]
    public function itRefusesAGrantTypeTheHandlerWasNotGiven(): void
    {
        // Given
        $codeOnly = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([$this->codeGrant]));

        // Then
        $this->expectException(UnsupportedGrantTypeException::class);

        // When
        $codeOnly->handle(
            $this->tenant,
            null,
            [
                'grant_type' => 'refresh_token',
                'client_id' => 'public-client',
            ],
            $this->context,
        );
    }

    /**
     * RFC 6749 §5.2 "unauthorized_client": the client is authenticated but not registered for the grant.
     */
    #[Test]
    public function itRefusesAGrantTheClientIsNotRegisteredFor(): void
    {
        // Given
        $this->refreshTokens->save(Tokens::refreshToken('the-token', $this->publicClient, $this->session, $this->clock->now()));

        // When
        try {
            $this->handler->handle($this->tenant, null, $this->publicRefresh(), $this->context);
            static::fail('The public client is not registered for refresh_token.');
        } catch (UnauthorizedClientException $exception) {
            // Then
            static::assertSame(400, $exception->statusCode);
            static::assertFalse($exception->redirectable);
        }
    }

    #[Test]
    public function aGrantTheClientIsNotRegisteredForRotatesNothing(): void
    {
        // Given
        $token = Tokens::refreshToken('the-token', $this->publicClient, $this->session, $this->clock->now());
        $this->refreshTokens->save($token);

        // When
        try {
            $this->handler->handle($this->tenant, null, $this->publicRefresh(), $this->context);
        } catch (UnauthorizedClientException) {
        }

        // Then
        static::assertFalse($token->isRotated());
    }

    /**
     * RFC 6749 §4.5: a grant the provider gains is served because it is wired and under the name it
     * gives itself; nothing of this endpoint, of the registration or of the document knows that name,
     * and the request reaches the grant all the same.
     */
    #[Test]
    public function itServesAGrantItKnowsNothingAbout(): void
    {
        // Given
        $client = Clients::confidential(
            $this->tenant,
            $this->hasher->hash(Clients::SECRET),
            Methods::clientSecretBasic($this->hasher),
            'invented-client',
            grantTypes: [Grants::invented()],
        );
        $this->clients->save($client);
        $handler = new TokenHandler($this->authenticator(), Proofs::verifier(), new Endpoints(), new ServedGrants([new FakeGrant(Grants::invented())]));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The fake grant grants nothing.');

        // When
        $handler->handle(
            $this->tenant,
            self::basic('invented-client', Clients::SECRET),
            [
                'grant_type' => 'urn:example:params:oauth:grant-type:invented',
            ],
            $this->context,
        );
    }

    /**
     * RFC 9449 §5: a request that proves a key gets tokens bound to it, and says so in "token_type", so
     * that a client knows to present them under the DPoP scheme (§7.1).
     */
    #[Test]
    public function aRequestThatProvesAKeyBindsTheTokensToIt(): void
    {
        // Given
        $this->codes->save(Tokens::code(
            'the-code',
            $this->publicClient,
            $this->session,
            $this->clock->now(),
            ['openid'],
            dpopKey: Proofs::thumbprintOf(Proofs::key()),
        ));

        // When
        $response = $this->handler->handle($this->tenant, null, $this->publicExchange(), $this->context, null, $this->proof());

        // Then
        static::assertSame('DPoP', $response->parameters()['token_type']);
        static::assertEquals(Proofs::thumbprintOf(Proofs::key()), $this->issuedConfirmation());
    }

    /**
     * RFC 9449 §5: a client that sends no proof keeps getting bearer tokens, which is what every client
     * that does not bind its tokens does.
     */
    #[Test]
    public function aRequestThatProvesNothingGetsABearerToken(): void
    {
        // Given
        $this->codes->save(Tokens::code('the-code', $this->publicClient, $this->session, $this->clock->now(), ['openid']));

        // When
        $response = $this->handler->handle($this->tenant, null, $this->publicExchange(), $this->context);

        // Then
        static::assertSame('Bearer', $response->parameters()['token_type']);
        static::assertNull($this->issuedConfirmation());
    }

    /**
     * RFC 9449 §10.1: the code was reserved for a key at the authorization request, and a token request
     * that proves another key does not collect it. A code taken on its way back through the browser is
     * worth nothing to whoever does not hold the key.
     */
    #[Test]
    public function aCodeReservedForAKeyIsNotExchangedByAnother(): void
    {
        // Given
        $this->codes->save(Tokens::code(
            'the-code',
            $this->publicClient,
            $this->session,
            $this->clock->now(),
            ['openid'],
            dpopKey: Proofs::thumbprintOf(Proofs::otherKey()),
        ));

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The authorization code is invalid.');

        // When
        $this->handler->handle($this->tenant, null, $this->publicExchange(), $this->context, null, $this->proof());
    }

    /**
     * A token is bound to one thing. A request proving a certificate and a key at once leaves the
     * provider to choose what the client meant, and is refused instead.
     */
    #[Test]
    public function aRequestThatProvesACertificateAndAKeyIsRefused(): void
    {
        // Given
        $client = Clients::withCertificateIdentity($this->tenant, new SubjectDistinguishedName('c=FR,o=Heidi Test,cn=heidi mtls client'));
        $this->clients->save($client);
        $this->codes->save(Tokens::code('the-code', $client, $this->session, $this->clock->now(), ['openid']));

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIs('invalid_dpop_proof: The tokens of a request are bound to one thing, and this request proves a certificate and a key (RFC 9449 section 5).');

        // When
        $this->handler->handle(
            $this->tenant,
            null,
            [
                'grant_type' => 'authorization_code',
                'code' => 'the-code',
                'redirect_uri' => 'https://mtls.example/callback',
                'client_id' => 'mtls-client',
                'code_verifier' => Tokens::CODE_VERIFIER,
            ],
            $this->context,
            Certificates::client(),
            $this->proof(),
        );
    }

    /**
     * FAPI 1.0 Advanced Final §5.2.2, RFC 8705 §3.4: the client of a profile that binds authenticates
     * with an assertion and presents a certificate all the same, and the tokens it comes for are bound
     * to that certificate.
     */
    #[Test]
    public function aClientRegisteredForCertificateBoundTokensGetsThemBoundToTheCertificateItPresented(): void
    {
        // Given
        $this->backchannelRecords->save($this->approvedBackchannelRequest());

        // When
        $this->backchannelHandler()->handle($this->tenant, null, $this->cibaExchange(), $this->context, Certificates::client());

        // Then
        static::assertEquals(CertificateConfirmation::ofCertificate(Certificates::client()), $this->issuedConfirmation());
    }

    /**
     * FAPI 1.0 Advanced Final §5.2.2: a token request of such a client that proves no certificate gets
     * no token at all, and is refused before anything is read of what it came to spend. The request
     * below comes for a backchannel request nobody has answered, and is refused rather than told to
     * come back later.
     */
    #[Test]
    #[DataProvider('provideRequestsThatProveNoCertificate')]
    public function aTokenRequestThatProvesNoCertificateIsRefusedRatherThanToldToComeBackLater(bool $provesAKey): void
    {
        // Given
        $this->backchannelRecords->save($this->unansweredBackchannelRequest());

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The tokens of this client are bound to the certificate it presents, and this request proves none (RFC 8705 section 3.4).');

        // When
        $this->backchannelHandler()->handle(
            $this->tenant,
            null,
            $this->cibaExchange(),
            $this->context,
            null,
            $provesAKey ? $this->proof() : null,
        );
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideRequestsThatProveNoCertificate(): iterable
    {
        yield 'nothing at all' => [false];
        yield 'a key instead' => [true];
    }

    /**
     * CIBA Core §11: the rule above is about what the request proves and about nothing else. The same
     * request presenting the certificate reaches the grant, and hears what the grant has to say.
     */
    #[Test]
    public function aRequestThatProvesItsCertificateIsToldToComeBackLaterWhileNobodyHasAnswered(): void
    {
        // Given
        $this->backchannelRecords->save($this->unansweredBackchannelRequest());

        // Then
        $this->expectException(AuthorizationPendingException::class);

        // When
        $this->backchannelHandler()->handle($this->tenant, null, $this->cibaExchange(), $this->context, Certificates::client());
    }

    private function authenticator(): ClientAuthenticator
    {
        return new ClientAuthenticator(
            $this->clients,
            Methods::all($this->hasher),
            Methods::requestParser(),
            $this->clock,
            $this->events,
            new FakeClientLoadBudget(),
        );
    }

    /**
     * @return array<string, string>
     */
    private function codeExchange(): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'client_id' => 'basic-client',
            'code_verifier' => Tokens::CODE_VERIFIER,
        ];
    }

    /**
     * @return array<string, string>
     */
    private function publicRefresh(): array
    {
        return [
            'grant_type' => 'refresh_token',
            'refresh_token' => 'the-token',
            'client_id' => 'public-client',
        ];
    }

    /**
     * @return array<string, string>
     */
    private function publicExchange(): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://spa.example/callback',
            'client_id' => 'public-client',
            'code_verifier' => Tokens::CODE_VERIFIER,
        ];
    }

    /**
     * The token endpoint of a provider serving the one grant a client of a FAPI-CIBA plan comes for.
     */
    private function backchannelHandler(): TokenHandler
    {
        return new TokenHandler(
            $this->authenticator(),
            Proofs::verifier(),
            new Endpoints(),
            new ServedGrants([new BackchannelAuthenticationGrant(
                $this->backchannelRecords,
                $this->issuer,
                new RefreshTokenDue(Grants::servedWithCiba()),
                new SymfonyUuidGenerator(),
                $this->clock,
            )]),
        );
    }

    /**
     * A backchannel request of that client that nobody has answered yet (CIBA Core §7).
     */
    private function unansweredBackchannelRequest(): BackchannelAuthenticationRecord
    {
        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf(self::AUTH_REQUEST_ID),
            Uuid::v7(),
            $this->boundClient,
            $this->session->user,
            new Scopes([new Scope('openid')]),
            null,
            null,
            [],
            null,
            null,
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
    }

    /**
     * The same request, approved by the user it named (CIBA Core §10.1).
     */
    private function approvedBackchannelRequest(): BackchannelAuthenticationRecord
    {
        $record = $this->unansweredBackchannelRequest();
        $record->approve(
            $this->session,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $this->clock->now(),
        );

        return $record;
    }

    /**
     * What that client sends to collect its tokens: the identifier of its request, and the assertion it
     * authenticates with (CIBA Core §10.1, OIDC Core §9).
     *
     * @return array<string, string>
     */
    private function cibaExchange(): array
    {
        return [
            'grant_type' => 'urn:openid:params:grant-type:ciba',
            'auth_req_id' => self::AUTH_REQUEST_ID,
            ...ClientAssertions::parameters(ClientAssertions::signedWithKey(
                ClientAssertions::claims('bound-terminal', $this->tenant->issuer->value, $this->clock->now()),
            )),
        ];
    }

    /**
     * A proof for the token endpoint of the tenant, made now.
     */
    private function proof(?JWK $key = null): string
    {
        return Proofs::proof('POST', Endpoints::of($this->tenant)->token, $this->clock->now(), null, [], [], $key);
    }

    /**
     * What the tokens that left are bound to, as the event that announced them says.
     */
    private function issuedConfirmation(): ?ConfirmationInterface
    {
        $issued = $this->events->of(TokensIssued::class);

        return $issued === [] ? static::fail('No token was issued.') : $issued[0]->confirmation;
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
