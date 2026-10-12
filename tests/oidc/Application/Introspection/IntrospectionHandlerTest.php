<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Introspection;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Grants;
use function base64_encode;
use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Introspection\IntrospectionHandler;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Application\Grant\RecordedGrants;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use Beffroi\Oidc\Domain\Introspection\IntrospectionResponse;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * The endpoint end to end below HTTP: tokens of both shapes, a real client authentication, the response
 * signed by the bridge of the core and verified the way Symfony's Oauth2TokenHandler verifies it.
 */
final class IntrospectionHandlerTest extends TestCase
{
    private Tenant $tenant;

    private AuthenticationSession $session;

    private Client $client;

    private Client $other;

    private Client $service;

    private MockClock $clock;

    private RequestContext $context;

    private Jwts $jwts;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryDeviceAuthorizationRecordRepository $deviceRecords;

    private InMemoryBackchannelAuthenticationRecordRepository $backchannelRecords;

    private InMemoryAccessTokenRepository $tokens;

    private IntrospectionHandler $handler;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $user = Fixtures::user($this->tenant);
        $this->clock = new MockClock('2026-09-17T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $this->session = Fixtures::session($user, $this->clock->now()->modify('-1 hour'));
        $hasher = new FakePasswordHasher();
        $this->client = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET), accessTokenShape: Shapes::opaque());
        $this->other = Clients::confidential($this->tenant, $hasher->hash(Clients::SECRET), Methods::clientSecretPost(), 'other');
        $this->service = Clients::service($this->tenant, $hasher->hash(Clients::SECRET), accessTokenShape: Shapes::opaque());
        $clients = new InMemoryClientRepository();
        foreach ([$this->client, $this->other, $this->service, Clients::public($this->tenant)] as $client) {
            $clients->save($client);
        }
        $this->jwts = new Jwts($this->tenant);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->deviceRecords = new InMemoryDeviceAuthorizationRecordRepository();
        $this->backchannelRecords = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save($this->session);
        $users = new InMemoryUserRepository();
        $users->save($user);
        $this->events = new RecordingEventDispatcher();
        $this->handler = new IntrospectionHandler(
            new ClientAuthenticator(
                $clients,
                Methods::all($hasher),
                Methods::requestParser(),
                $this->clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            new Endpoints(),
            new AccessTokenInspector(
                AccessTokenShapes::verifier(
                    new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                    $clients,
                    $this->tokens,
                    Subjects::publicKind(),
                ),
                $sessions,
                new RecordedGrants([$this->grants, $this->deviceRecords, $this->backchannelRecords]),
                Subjects::personOfAToken($users),
            ),
            $this->jwts->signer,
            Algorithms::all(),
            $this->events,
        );
    }

    /**
     * RFC 7662 §2.2: an opaque token of the caller, described from its record.
     */
    #[Test]
    public function itDescribesAnOpaqueTokenToTheClientItWasIssuedTo(): void
    {
        // Given
        $code = $this->code($this->client, ['openid', 'email']);
        $token = $this->opaqueToken($code);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
                'token_type_hint' => 'access_token',
            ],
            $this->context,
            false,
        );

        // Then
        static::assertSame(
            [
                'active' => true,
                'scope' => 'openid email',
                'client_id' => 'oidc-demo',
                'token_type' => 'Bearer',
                'exp' => $this->clock->now()->modify('+10 minutes')->getTimestamp(),
                'iat' => $this->clock->now()->getTimestamp(),
                'sub' => 'alice-subject',
                'aud' => 'oidc-demo',
                'iss' => 'https://id.acme.example',
                'auth_time' => $this->session->authenticatedAt()->getTimestamp(),
                'acr' => '1',
                'amr' => ['pwd'],
                'sid' => $this->session->id->toRfc4122(),
                'grant_id' => $code->grantId->toRfc4122(),
            ],
            $response->members,
        );
        static::assertNull($response->jwt);
    }

    /**
     * Issue #589: a resource server told who a token names is one of the two reads where a personal datum
     * leaves this provider, so it is an act, naming the client that asked and the person by the subject
     * their account carries.
     */
    #[Test]
    public function describingATokenOfAPersonIsAnAct(): void
    {
        // Given
        $token = $this->opaqueToken($this->code($this->client, ['openid']));

        // When
        $this->describe($token, self::basic('oidc-demo'));

        // Then
        $acts = $this->events->of(IntrospectionAnswered::class);
        static::assertCount(1, $acts);
        static::assertSame('oidc-demo', $acts[0]->clientId);
        static::assertTrue($acts[0]->subject()->equals($this->session->user->subject));
    }

    /**
     * RFC 7662 §2.2: an inactive answer carries no other member, so it says a read of nobody; writing an
     * act of it would also let whoever asks after tokens they do not hold reach the journal of somebody
     * (issue #589).
     */
    #[Test]
    public function anInactiveAnswerIsNoAct(): void
    {
        // When
        $this->describe('unknown', self::basic('oidc-demo'));

        // Then
        static::assertSame([], $this->events->of(IntrospectionAnswered::class));
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself names that client and no person, so describing it
     * hands no personal datum to anybody and is no act of this register (issue #589).
     */
    #[Test]
    public function describingATokenAClientHoldsForItselfIsNoAct(): void
    {
        // Given
        $token = $this->opaqueIssuer()->issue(
            new ClientAuthorization(
                Grants::clientCredentials(),
                Uuid::v7(),
                $this->service,
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
            ),
            $this->clock->now(),
        )->value;

        // When
        $response = $this->describe($token, self::basic('batch'));

        // Then
        static::assertTrue($response->isActive());
        static::assertSame([], $this->events->of(IntrospectionAnswered::class));
    }

    /**
     * RFC 8705 §3.2: the answer tells the resource server what the token is bound to, so that it can ask
     * its own caller to present that certificate again.
     */
    #[Test]
    public function itTellsWhatABoundTokenIsBoundTo(): void
    {
        // Given
        $certificate = Certificates::client();
        $token = $this->opaqueIssuer()->issue(
            UserAuthorization::fromAuthorizationCode(
                Grants::authorizationCode(),
                $this->code($this->client, ['openid']),
                CertificateConfirmation::ofCertificate($certificate),
            ),
            $this->clock->now(),
        )->value;

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
            false,
        );

        // Then
        static::assertSame(
            [
                'x5t#S256' => $certificate->x5tS256(),
            ],
            $response->members['cnf'],
        );
    }

    /**
     * RFC 7662 §2.2: a self-contained token is described the same way, from its claims, for a resource
     * server that would rather not verify it itself.
     */
    #[Test]
    public function itDescribesAJwtTokenAsWell(): void
    {
        // Given
        $code = $this->code($this->other, ['openid']);
        $token = new JwtAccessTokenIssuer($this->jwts->signer, Subjects::publicKind(), Algorithms::all(), new SymfonyUuidGenerator())->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            $this->clock->now(),
        )->value;

        // When
        $response = $this->handler->handle(
            $this->tenant,
            null,
            [
                'client_id' => 'other',
                'client_secret' => Clients::SECRET,
                'token' => $token,
            ],
            $this->context,
            false,
        );

        // Then
        static::assertTrue($response->isActive());
        static::assertSame('other', $response->members['client_id']);
        static::assertSame('alice-subject', $response->members['sub']);
        static::assertSame($code->grantId->toRfc4122(), $response->members['grant_id']);
    }

    /**
     * RFC 7662 §2.2 and §4: a token that is not the caller's, or not one to honour, is "active": false and
     * nothing else, whatever the reason.
     *
     * @param callable(self): string $token
     */
    #[Test]
    #[DataProvider('provideInactiveTokens')]
    public function itSaysNothingOfATokenTheCallerMayNotHonour(callable $token): void
    {
        // Given
        $value = $token($this);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $value,
            ],
            $this->context,
            false,
        );

        // Then
        static::assertSame(
            [
                'active' => false,
            ],
            $response->members,
        );
    }

    /**
     * @return iterable<string, array{callable(self): string}>
     */
    public static function provideInactiveTokens(): iterable
    {
        yield 'unknown' => [
            static fn (): string => 'unknown',
        ];
        yield 'of another client' => [
            static fn (self $test): string => $test->opaqueToken($test->code($test->other)),
        ];
        yield 'expired' => [
            static fn (self $test): string => $test->opaqueToken($test->code($test->client), $test->clock->now()->modify('-10 minutes')),
        ];
        yield 'of a revoked grant' => [static function (self $test): string {
            $code = $test->code($test->client);
            $token = $test->opaqueToken($code);
            $code->revoke($test->clock->now());

            return $token;
        }];
        yield 'of a disabled user' => [static function (self $test): string {
            $token = $test->opaqueToken($test->code($test->client));
            $test->session->user->disable($test->clock->now());

            return $token;
        }];
        yield 'a JWT of another issuer' => [
            static fn (): string => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLm90aGVyLmV4YW1wbGUifQ.c2ln',
        ];
    }

    /**
     * RFC 7662 §2.1: the caller authenticates as a client; a wrong secret is invalid_client, 401, with the
     * challenge of the token endpoint.
     */
    #[Test]
    public function itRefusesACallerThatDoesNotAuthenticate(): void
    {
        // When
        try {
            $this->handler->handle(
                $this->tenant,
                self::basic('oidc-demo', 'wrong'),
                [
                    'token' => 'whatever',
                ],
                $this->context,
                false,
            );
            static::fail('The caller should have been refused.');
        } catch (InvalidClientException $exception) {
            // Then
            static::assertSame(401, $exception->statusCode);
            static::assertSame('Basic realm="https://id.acme.example"', $exception->challenge);
        }
    }

    /**
     * RFC 7662 §2.1: a public client has nothing to authenticate with, and the endpoint requires it
     * against token scanning.
     */
    #[Test]
    public function itRefusesAPublicClient(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessageIs('invalid_client: The introspection endpoint requires client authentication (RFC 7662 section 2.1); a public client has none.');

        // When
        $this->handler->handle(
            $this->tenant,
            null,
            [
                'client_id' => 'spa',
                'token' => 'whatever',
            ],
            $this->context,
            false,
        );
    }

    /**
     * RFC 7662 §2.1: "token" is required; a hint that is not a string is not read either.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideMalformedRequests')]
    public function itRefusesAMalformedRequest(array $parameters, string $message): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: ' . $message);

        // When
        $this->handler->handle($this->tenant, self::basic('oidc-demo'), $parameters, $this->context, false);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedRequests(): iterable
    {
        yield 'no token' => [[], 'The token parameter is missing.'];
        yield 'empty token' => [
            [
                'token' => '',
            ],
            'The token parameter is missing.',
        ];
        yield 'token repeated' => [
            [
                'token' => ['a', 'b'],
            ],
            'The token parameter must be a single string.',
        ];
        yield 'hint repeated' => [
            [
                'token' => 'a',
                'token_type_hint' => ['access_token'],
            ],
            'The token_type_hint parameter must be a single string.',
        ];
    }

    /**
     * RFC 9701 §4 and §5: when asked, the members travel as the "token_introspection" claim of a JWT that
     * names the provider, the caller and the moment, signed with the active key under the "typ" of §5,
     * which is what Symfony's Oauth2TokenHandler checks before reading the members.
     */
    #[Test]
    public function itSignsTheResponseWhenAsked(): void
    {
        // Given
        $code = $this->code($this->client);
        $token = $this->opaqueToken($code);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
            true,
        );

        // Then
        $jwt = $response->jwt ?? static::fail('The response is signed.');
        $jws = new CompactSerializer()->unserialize($jwt);
        static::assertTrue(new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet(
            $jws,
            JWKSet::createFromKeyData($this->jwts->keys->publicKeys($this->tenant)->toJwks()),
            0,
        ));
        static::assertSame('token-introspection+jwt', $jws->getSignature(0)->getProtectedHeaderParameter('typ'));
        static::assertSame($this->jwts->key->kid, $jws->getSignature(0)->getProtectedHeaderParameter('kid'));
        $claims = Jwts::decode((string) $jws->getPayload());
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame('oidc-demo', $claims['aud']);
        static::assertSame($this->clock->now()->getTimestamp(), $claims['iat']);
        static::assertSame($response->members, $claims['token_introspection']);
        static::assertTrue($response->isActive());
    }

    /**
     * RFC 9701 §5: an inactive token is signed too; the caller asked for a JWT and gets one.
     */
    #[Test]
    public function anInactiveTokenIsSignedToo(): void
    {
        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => 'unknown',
            ],
            $this->context,
            true,
        );

        // Then
        $jwt = $response->jwt ?? static::fail('The response is signed.');
        static::assertSame(
            [
                'active' => false,
            ],
            Jwts::decode(Jwts::rawPayload($jwt))['token_introspection'],
        );
    }

    /**
     * RFC 8628 §3.4: the tokens of the device grant descend from the device authorization request, so it is
     * that record introspection asks whether the grant is still alive.
     */
    #[Test]
    public function itDescribesATokenOfTheDeviceGrantAsActive(): void
    {
        // Given
        $record = Tokens::approvedDeviceRecord($this->client, $this->session, $this->clock->now());
        $this->deviceRecords->save($record);
        $token = $this->tokenOfTheRecord($record->grantId, $record->scopes);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
            false,
        );

        // Then
        static::assertSame($record->grantId->toRfc4122(), $response->members['grant_id']);
    }

    /**
     * CIBA Core §10.1: the same of the backchannel grant, whose record is the grant too.
     */
    #[Test]
    public function itDescribesATokenOfTheBackchannelGrantAsActive(): void
    {
        // Given
        $record = Tokens::approvedBackchannelRecord($this->client, $this->session, $this->clock->now());
        $this->backchannelRecords->save($record);
        $token = $this->tokenOfTheRecord($record->grantId, $record->scopes);

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('oidc-demo'),
            [
                'token' => $token,
            ],
            $this->context,
            false,
        );

        // Then
        static::assertSame($record->grantId->toRfc4122(), $response->members['grant_id']);
    }

    /**
     * One request of a caller describing one token, the shape the three tests of the act above share.
     */
    private function describe(string $token, string $authorization): IntrospectionResponse
    {
        return $this->handler->handle(
            $this->tenant,
            $authorization,
            [
                'token' => $token,
            ],
            $this->context,
            false,
        );
    }

    private function tokenOfTheRecord(Uuid $grantId, Scopes $scopes): string
    {
        return $this->opaqueIssuer()->issue(
            new UserAuthorization(
                Grants::deviceCode(),
                $grantId,
                $this->client,
                $this->session,
                $scopes,
                $scopes,
                null,
                null,
                AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            ),
            $this->clock->now(),
        )->value;
    }

    /**
     * @param list<string> $scopes
     */
    private function code(Client $client, array $scopes = ['openid']): AuthorizationCode
    {
        $code = Tokens::code('the-code-of-' . $client->registration->clientId, $client, $this->session, $this->clock->now(), $scopes);
        $this->grants->save($code);

        return $code;
    }

    private function opaqueToken(AuthorizationCode $code, ?DateTimeImmutable $issuedAt = null): string
    {
        $issuedAt ??= $this->clock->now();

        return $this->opaqueIssuer()->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            $issuedAt,
        )->value;
    }

    private function opaqueIssuer(): OpaqueAccessTokenIssuer
    {
        return new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer());
    }

    private static function basic(string $clientId, string $secret = Clients::SECRET): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
