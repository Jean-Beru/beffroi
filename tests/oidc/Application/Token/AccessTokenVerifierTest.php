<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Exception\RuntimeException as CoreRuntimeException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\AccessTokenVerifier;
use Beffroi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\ServedAccessTokenShapes;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Tests\Fixture\Bindings;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use Beffroi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Throwable;

final class AccessTokenVerifierTest extends TestCase
{
    private const string TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2lkLmFjbWUuZXhhbXBsZSJ9.c2lnbmF0dXJl';

    private const string ACCOUNT = 'alice-as-this-provider-knows-her';

    private const string PAYLOAD = '{"iss":"https://id.acme.example","exp":1789467000,"aud":"spa","sub":"alice-subject","client_id":"spa","iat":1789466400,"jti":"6f1c2b7e-1d2a-4c3b-8e9f-0a1b2c3d4e5f","auth_time":1789466400,"acr":"1","amr":["pwd"],"scope":"openid profile","sid":"01997b9e-0000-7000-8000-000000000000","grant_id":"01997b9e-0000-7000-8000-00000000000a"}';

    private Tenant $tenant;

    private Client $client;

    private FakeJwsVerifier $jws;

    private InMemoryAccessTokenRepository $storedTokens;

    private AccessTokenVerifier $verifier;

    /**
     * Architecture §4.6
     */
    private string $opaque;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::public($this->tenant, resources: Clients::resources());
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $this->jws = new FakeJwsVerifier();
        $this->storedTokens = new InMemoryAccessTokenRepository();
        $this->opaque = Secrets::draw();
        $this->verifier = AccessTokenShapes::verifier($this->jws, $clients, $this->storedTokens, Subjects::publicKind());
    }

    /**
     * RFC 9068 §2.2, §2.2.3, §4, RFC 8693 §4.2, Architecture §4.6, OIDC Core §5.5
     */
    #[Test]
    public function itReadsATokenTheIssuerMinted(): void
    {
        // Given
        $session = Fixtures::session(Fixtures::user($this->tenant));
        $jwts = new Jwts($this->tenant);
        $code = Tokens::code(
            'the-code',
            $this->client,
            $session,
            Fixtures::now(),
            ['openid', 'email'],
            claims: ClaimsRequest::fromJson('{"userinfo":{"name":null,"picture":{"essential":true}},"id_token":{"email":null}}'),
        );
        $minted = Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
            ),
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            Fixtures::now(),
        );
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $verifier = AccessTokenShapes::verifier(
            new JwtLibraryJwsVerifier($jwts->keys, Algorithms::all()),
            $clients,
            $this->storedTokens,
            Subjects::publicKind(),
        );

        // When
        $token = $verifier->verify($this->tenant, $minted->value, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($this->client, $token->client);
        static::assertSame('alice-subject', (string) $token->subject);
        static::assertSame(['openid', 'email'], $token->scopes?->values());
        static::assertTrue($token->scopes->has(Scope::openid()));
        static::assertTrue($token->scopes->has(new Scope('email')));
        static::assertFalse($token->scopes->has(new Scope('profile')));
        static::assertSame(['name', 'picture'], $token->userinfoClaims);
        static::assertTrue($code->grantId->equals($token->grantId));
        $signIn = $token->signIn ?? static::fail('The token descends from a sign-in.');
        static::assertTrue($session->id->equals($signIn->sessionId));
        static::assertEquals($session->authenticatedAt(), $signIn->authentication->authenticatedAt);
        static::assertSame(['pwd'], $signIn->authentication->methods);
        static::assertSame('1', $signIn->authentication->contextClass);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itReadsTheRecordOfAnOpaqueToken(): void
    {
        // Given
        $session = Fixtures::session(Fixtures::user($this->tenant));
        $record = Tokens::storedAccessToken(
            $this->opaque,
            $this->client,
            $session,
            Fixtures::now(),
            scopes: ['openid', 'email'],
            claims: ClaimsRequest::fromJson('{"userinfo":{"name":null,"picture":{"essential":true}}}'),
        );
        $this->storedTokens->save($record);

        // When
        $token = $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($this->client, $token->client);
        static::assertSame('alice-subject', (string) $token->subject);
        static::assertSame(['openid', 'email'], $token->scopes?->values());
        static::assertSame(['name', 'picture'], $token->userinfoClaims);
        static::assertTrue($record->grantId->equals($token->grantId));
        $signIn = $token->signIn ?? static::fail('The token descends from a sign-in.');
        static::assertTrue($session->id->equals($signIn->sessionId));
        static::assertEquals($session->authenticatedAt(), $signIn->authentication->authenticatedAt);
        static::assertSame(['pwd'], $signIn->authentication->methods);
        static::assertSame('1', $signIn->authentication->contextClass);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function itReadsTheAuthorizationDetailsOfASelfContainedToken(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details('acct-4711', ['read']);
        $this->knows(self::with([
            'authorization_details' => $details->toClaim(),
        ]));

        // When
        $token = $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertTrue($token->authorizationDetails?->equals($details));
    }

    #[Test]
    public function itRefusesASelfContainedTokenNamingATypeNobodyServes(): void
    {
        // Given
        $this->knows(self::with([
            'authorization_details' => [
                [
                    'type' => AuthorizationDetailTypes::UNSERVED,
                    'account' => 'acct-4711',
                ],
            ],
        ]));

        // Then
        $this->expectException(InvalidTokenException::class);

        // When
        $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now()->modify('+9 minutes'));
    }

    /**
     * RFC 9396 §9
     */
    #[Test]
    public function itReadsTheAuthorizationDetailsOfTheRecordOfAnOpaqueToken(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details('acct-4711', ['read']);
        $this->storedTokens->save(Tokens::storedAccessToken(
            $this->opaque,
            $this->client,
            Fixtures::session(Fixtures::user($this->tenant)),
            Fixtures::now(),
            authorizationDetails: $details,
        ));

        // When
        $token = $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertTrue($token->authorizationDetails?->equals($details));
    }

    /**
     * RFC 8693 §2.2.1
     */
    #[Test]
    public function itReadsThePersonASelfContainedTokenSaysItIsAbout(): void
    {
        // Given
        $this->knows(self::with([
            'person' => Subjects::sealedPerson()->claim(Fixtures::tenant(), new Subject(self::ACCOUNT)),
        ]));

        // When
        $token = $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(self::ACCOUNT, (string) $token->person);
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function itNamesNobodyForASelfContainedTokenCarryingNoPerson(): void
    {
        // Given
        $this->knows(self::PAYLOAD);

        // When
        $token = $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertNull($token->person);
    }

    /**
     * RFC 6749 §4.4, RFC 9068 §2.2
     */
    #[Test]
    public function itReadsASelfContainedTokenNobodySignedInFor(): void
    {
        // Given
        $jwts = new Jwts($this->tenant);
        $service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $clients = new InMemoryClientRepository();
        $clients->save($service);
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $service,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $minted = Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
            ),
            $authorization,
            Fixtures::now(),
        );
        $verifier = AccessTokenShapes::verifier(
            new JwtLibraryJwsVerifier($jwts->keys, Algorithms::all()),
            $clients,
            $this->storedTokens,
            Subjects::publicKind(),
        );

        // When
        $token = $verifier->verify($this->tenant, $minted->value, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertNull($token->signIn);
        static::assertSame('batch', (string) $token->subject);
        static::assertSame([Clients::CALENDAR], $token->audience->values);
        static::assertSame(['invoices.read'], $token->scopes?->values());
        static::assertSame([], $token->userinfoClaims);
        static::assertTrue($authorization->grantId->equals($token->grantId));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itReadsTheRecordOfAnOpaqueTokenNobodySignedInFor(): void
    {
        // Given
        $service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $record = Tokens::storedClientAccessToken($this->opaque, $service, Fixtures::now());
        $this->storedTokens->save($record);
        $clients = new InMemoryClientRepository();
        $clients->save($service);
        $verifier = AccessTokenShapes::verifier($this->jws, $clients, $this->storedTokens, Subjects::publicKind());

        // When
        $token = $verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertNull($token->signIn);
        static::assertSame('batch', (string) $token->subject);
        static::assertSame([Clients::CALENDAR], $token->audience->values);
        static::assertSame([], $token->userinfoClaims);
        static::assertTrue($record->grantId->equals($token->grantId));
    }

    /**
     * RFC 8693 §2.2.1, §4.1
     */
    #[Test]
    public function itReadsTheRecordOfAnOpaqueTokenSomebodyHoldsForItsSubject(): void
    {
        // Given
        $session = Fixtures::session(Fixtures::user($this->tenant));
        $gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $actor = new Actor(new Subject('gateway'), new Actor(new Subject('first-hop')));
        $record = Tokens::storedSubjectAccessToken(
            $this->opaque,
            $gateway,
            new Subject('alice-subject'),
            Fixtures::now(),
            session: $session,
            actor: $actor,
        );
        $this->storedTokens->save($record);
        $clients = new InMemoryClientRepository();
        $clients->save($gateway);
        $verifier = AccessTokenShapes::verifier($this->jws, $clients, $this->storedTokens, Subjects::publicKind());

        // When
        $token = $verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame('alice-subject', (string) $token->subject);
        static::assertTrue($token->signIn?->sessionId->equals($session->id));
        static::assertTrue($token->actor?->equals($actor));
        static::assertSame([Clients::CALENDAR], $token->audience->values);
    }

    /**
     * RFC 8693 §1.3
     */
    #[Test]
    public function itReadsTheRecordOfAnImpersonationWithoutAnActor(): void
    {
        // Given
        $gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->storedTokens->save(Tokens::storedSubjectAccessToken($this->opaque, $gateway, new Subject('alice-subject'), Fixtures::now()));
        $clients = new InMemoryClientRepository();
        $clients->save($gateway);
        $verifier = AccessTokenShapes::verifier($this->jws, $clients, $this->storedTokens, Subjects::publicKind());

        // When
        $token = $verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertNull($token->actor);
        static::assertNull($token->signIn);
    }

    /**
     * RFC 8693 §4.1
     */
    #[Test]
    public function itReadsTheChainOfActorsOfASelfContainedToken(): void
    {
        // Given
        $this->knows('{"iss":"https://id.acme.example","exp":1789467000,"aud":"spa","sub":"alice-subject","client_id":"spa","iat":1789466400,'
        . '"jti":"6f1c2b7e-1d2a-4c3b-8e9f-0a1b2c3d4e5f","scope":"openid","grant_id":"01997b9e-0000-7000-8000-00000000000a",'
        . '"act":{"sub":"gateway","act":{"sub":"first-hop"}}}');

        // When
        $token = $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now());

        // Then
        static::assertTrue($token->actor?->equals(new Actor(new Subject('gateway'), new Actor(new Subject('first-hop')))));
    }

    /**
     * RFC 8707 §2
     *
     * @param list<string>|null $resources
     * @param list<string> $audience
     */
    #[Test]
    #[DataProvider('provideStoredResources')]
    public function itReadsWhoAnOpaqueTokenIsAddressedTo(?array $resources, array $audience): void
    {
        // Given
        $this->storedTokens->save(Tokens::storedAccessToken(
            $this->opaque,
            $this->client,
            Fixtures::session(Fixtures::user($this->tenant)),
            Fixtures::now(),
            resources: $resources === null ? null : ResourceIndicators::of($resources),
        ));

        // When
        $token = $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now());

        // Then
        static::assertSame($audience, $token->audience->values);
    }

    /**
     * @return iterable<string, array{list<string>|null, list<string>}>
     */
    public static function provideStoredResources(): iterable
    {
        yield 'no resource' => [null, ['spa']];
        yield 'one resource' => [[Clients::CALENDAR], [Clients::CALENDAR]];
        yield 'two resources' => [
            [Clients::CALENDAR, Clients::CONTACTS],
            [Clients::CALENDAR, Clients::CONTACTS],
        ];
    }

    #[Test]
    public function anOpaqueTokenWithoutAClaimsRequestAskedForNoClaimByName(): void
    {
        // Given
        $this->storedTokens->save(Tokens::storedAccessToken(
            $this->opaque,
            $this->client,
            Fixtures::session(Fixtures::user($this->tenant)),
            Fixtures::now(),
        ));

        // When
        $token = $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now());

        // Then
        static::assertSame([], $token->userinfoClaims);
    }

    /**
     * RFC 6750 §3.1
     *
     * @param callable(self): void $given
     */
    #[Test]
    #[DataProvider('provideUnknownOpaqueTokens')]
    public function itRefusesAnOpaqueTokenItDoesNotKeep(callable $given): void
    {
        // Given
        $given($this);

        // When
        try {
            $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now());
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            // Then
            static::assertSame('invalid_token', $exception->error);
            static::assertSame('The access token is not an access token issued by this provider.', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{callable(self): void}>
     */
    public static function provideUnknownOpaqueTokens(): iterable
    {
        yield 'no record' => [static function (): void {
        }];
        yield 'another value' => [static function (self $test): void {
            $test->storedTokens->save(Tokens::storedAccessToken(
                'another-token',
                $test->client,
                Fixtures::session(Fixtures::user($test->tenant)),
                Fixtures::now(),
            ));
        }];
        yield 'a record of another tenant' => [static function (self $test): void {
            $other = Fixtures::tenant('other', 'https://id.other.example');
            $test->storedTokens->save(Tokens::storedAccessToken(
                $test->opaque,
                Clients::public($other),
                Fixtures::session(Fixtures::user($other)),
                Fixtures::now(),
            ));
        }];
    }

    /**
     * RFC 7519 §4.1.4
     */
    #[Test]
    public function itRefusesAnExpiredOpaqueToken(): void
    {
        // Given
        $this->storedTokens->save(Tokens::storedAccessToken(
            $this->opaque,
            $this->client,
            Fixtures::session(Fixtures::user($this->tenant)),
            Fixtures::now(),
        ));

        // When
        try {
            $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+10 minutes'));
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            // Then
            static::assertSame('The access token expired.', $exception->errorDescription);
        }
    }

    /**
     * RFC 7519 §4.1.3, RFC 9068 §2.2.3, Architecture §4.6
     *
     * @param list<string> $expectedClaims
     */
    #[Test]
    #[DataProvider('provideValidPayloads')]
    public function itReadsTheClaimsOfAnAccessTokenOfThisProvider(
        string $payload,
        string $expectedScopes,
        array $expectedClaims,
        int $expectedExpiry = 1789467000,
    ): void {
        // Given
        $this->knows($payload);

        // When
        $token = $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now());

        // Then
        static::assertSame($this->client, $token->client);
        static::assertSame('alice-subject', (string) $token->subject);
        static::assertSame($expectedScopes, (string) $token->scopes);
        static::assertSame($expectedClaims, $token->userinfoClaims);
        static::assertSame($expectedExpiry, $token->expiresAt->getTimestamp());
    }

    /**
     * @return iterable<string, array{string, string, list<string>, 3?: int}>
     */
    public static function provideValidPayloads(): iterable
    {
        yield 'as issued' => [self::PAYLOAD, 'openid profile', []];
        yield 'audience list' => [
            self::with([
                'aud' => [Clients::CALENDAR, Clients::CONTACTS],
            ]),
            'openid profile',
            [],
        ];
        yield 'no scope' => [self::without('scope'), '', []];
        yield 'claims asked for by name' => [
            self::with([
                'userinfo_claims' => ['email', 'name'],
            ]),
            'openid profile',
            ['email', 'name'],
        ];
        yield 'claims asked for by name, none' => [
            self::with([
                'userinfo_claims' => [],
            ]),
            'openid profile',
            [],
        ];
        yield 'one second before expiry' => [
            self::with([
                'exp' => 1789466401,
            ]),
            'openid profile',
            [],
            1789466401,
        ];
    }

    /**
     * RFC 6750 §3.1, RFC 9068 §4, RFC 8725 §3.11
     *
     * @param array<string, string>|null $header
     * @param class-string<Throwable>|null $cause
     */
    #[Test]
    #[DataProvider('provideForeignTokens')]
    public function itRefusesWhatIsNotAnAccessTokenOfThisProvider(?string $payload, ?array $header = null, ?string $cause = null): void
    {
        // Given
        if ($payload !== null) {
            $this->knows($payload, $header);
        }

        // When
        try {
            $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now());
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            // Then
            static::assertSame('invalid_token', $exception->error);
            static::assertSame(401, $exception->statusCode);
            static::assertFalse($exception->redirectable);
            static::assertSame('The access token is not an access token issued by this provider.', $exception->errorDescription);
            if ($cause === null) {
                static::assertNull($exception->getPrevious());
            } else {
                static::assertInstanceOf($cause, $exception->getPrevious());
            }
        }
    }

    /**
     * @return iterable<string, array{string|null, array<string, string>|null, class-string<Throwable>|null}>
     */
    public static function provideForeignTokens(): iterable
    {
        yield 'does not verify' => [null, null, InvalidJwsException::class];
        yield 'not JSON' => ['not json', null, JsonException::class];
        yield 'too deep' => [
            self::with([
                'act' => [
                    'act' => [
                        'act' => [
                            'act' => [
                                'act' => [
                                    'act' => [
                                        'sub' => 'gateway',
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ]),
            null,
            JsonException::class,
        ];
        yield 'a JSON string' => ['"iss"', null, null];
        yield 'a JSON list' => ['["https://id.acme.example"]', null, null];
        yield 'no typ header' => [self::PAYLOAD, [], null];
        yield 'another typ header' => [
            self::PAYLOAD,
            [
                'typ' => 'JWT',
            ],
            null,
        ];
        yield 'typ header in another case' => [
            self::PAYLOAD,
            [
                'typ' => 'AT+JWT',
            ],
            null,
        ];
        yield 'no iss' => [self::without('iss'), null, null];
        yield 'another iss' => [
            self::with([
                'iss' => 'https://id.other.example',
            ]),
            null,
            null,
        ];
        yield 'no exp' => [self::without('exp'), null, null];
        yield 'exp as a string' => [
            self::with([
                'exp' => '1789467000',
            ]),
            null,
            null,
        ];
        yield 'exp as a float' => [
            self::with([
                'exp' => 1789467000.5,
            ]),
            null,
            null,
        ];
        yield 'no client_id' => [self::without('client_id'), null, null];
        yield 'client_id not a string' => [
            self::with([
                'client_id' => 1,
            ]),
            null,
            null,
        ];
        yield 'unknown client' => [
            self::with([
                'client_id' => 'other',
            ]),
            null,
            null,
        ];
        yield 'no aud' => [self::without('aud'), null, InvalidArgumentException::class];
        yield 'aud of another client' => [
            self::with([
                'aud' => 'other',
            ]),
            null,
            null,
        ];
        yield 'aud list without the client' => [
            self::with([
                'aud' => ['api', 'other'],
            ]),
            null,
            null,
        ];
        yield 'aud of a resource the client is not registered for' => [
            self::with([
                'aud' => 'https://files.example.com/',
            ]),
            null,
            null,
        ];
        yield 'aud list holding a resource the client is not registered for' => [
            self::with([
                'aud' => [Clients::CALENDAR, 'https://files.example.com/'],
            ]),
            null,
            null,
        ];
        yield 'aud as an object' => [
            self::with([
                'aud' => [
                    'spa' => 'spa',
                ],
            ]),
            null,
            InvalidArgumentException::class,
        ];
        yield 'aud as a number' => [
            self::with([
                'aud' => 1,
            ]),
            null,
            InvalidArgumentException::class,
        ];
        yield 'aud as an object holding the client under the key 0' => [
            self::with([
                'aud' => (object) [
                    '0' => 'spa',
                ],
            ]),
            null,
            InvalidArgumentException::class,
        ];
        yield 'no sub' => [self::without('sub'), null, null];
        yield 'no iat' => [self::without('iat'), null, null];
        yield 'iat as a string' => [
            self::with([
                'iat' => '1789466400',
            ]),
            null,
            null,
        ];
        yield 'exp not after iat' => [
            self::with([
                'iat' => 1789467000,
            ]),
            null,
            null,
        ];
        yield 'no auth_time' => [self::without('auth_time'), null, Throwable::class];
        yield 'no sid' => [self::without('sid'), null, null];
        yield 'an auth_time without a sid' => [self::withoutAll(['sid', 'acr', 'amr']), null, null];
        yield 'an acr without a sid' => [self::withoutAll(['sid', 'auth_time', 'amr']), null, null];
        yield 'an amr without a sid' => [self::withoutAll(['sid', 'auth_time', 'acr']), null, null];
        yield 'sid not a UUID' => [
            self::with([
                'sid' => 'the-session',
            ]),
            null,
            null,
        ];
        yield 'no acr' => [self::without('acr'), null, Throwable::class];
        yield 'acr empty' => [
            self::with([
                'acr' => '',
            ]),
            null,
            Throwable::class,
        ];
        yield 'no amr' => [self::without('amr'), null, Throwable::class];
        yield 'amr not a list' => [
            self::with([
                'amr' => 'pwd',
            ]),
            null,
            Throwable::class,
        ];
        yield 'amr with an empty value' => [
            self::with([
                'amr' => [''],
            ]),
            null,
            Throwable::class,
        ];
        yield 'amr empty' => [
            self::with([
                'amr' => [],
            ]),
            null,
            Throwable::class,
        ];
        yield 'amr with a value that is not a method reference' => [
            self::with([
                'amr' => ['not a method'],
            ]),
            null,
            Throwable::class,
        ];
        yield 'acr with a space' => [
            self::with([
                'acr' => 'level one',
            ]),
            null,
            Throwable::class,
        ];
        yield 'no grant_id' => [self::without('grant_id'), null, null];
        yield 'grant_id not a string' => [
            self::with([
                'grant_id' => 1,
            ]),
            null,
            null,
        ];
        yield 'grant_id not a UUID' => [
            self::with([
                'grant_id' => 'the-grant',
            ]),
            null,
            null,
        ];
        yield 'sub not a string' => [
            self::with([
                'sub' => 1,
            ]),
            null,
            null,
        ];
        yield 'sub empty' => [
            self::with([
                'sub' => '',
            ]),
            null,
            Throwable::class,
        ];
        yield 'scope not a string' => [
            self::with([
                'scope' => ['openid'],
            ]),
            null,
            Throwable::class,
        ];
        yield 'scope empty' => [
            self::with([
                'scope' => '',
            ]),
            null,
            Throwable::class,
        ];
        yield 'scope with two spaces' => [
            self::with([
                'scope' => 'openid  profile',
            ]),
            null,
            Throwable::class,
        ];
        yield 'userinfo_claims not a list' => [
            self::with([
                'userinfo_claims' => 'email',
            ]),
            null,
            null,
        ];
        yield 'userinfo_claims as an object' => [
            self::with([
                'userinfo_claims' => [
                    'email' => null,
                ],
            ]),
            null,
            null,
        ];
        yield 'userinfo_claims with a number' => [
            self::with([
                'userinfo_claims' => ['email', 1],
            ]),
            null,
            null,
        ];
        yield 'userinfo_claims with an empty name' => [
            self::with([
                'userinfo_claims' => [''],
            ]),
            null,
            null,
        ];
        yield 'a person that is not a string' => [
            self::with([
                'person' => 1,
            ]),
            null,
            null,
        ];
        yield 'a person that is not an envelope' => [
            self::with([
                'person' => self::ACCOUNT,
            ]),
            null,
            CoreRuntimeException::class,
        ];
        yield 'a person sealed for another tenant' => [
            self::with([
                'person' => Subjects::sealedPerson()->claim(Fixtures::tenant('other', 'https://id.other.example'), new Subject(self::ACCOUNT)),
            ]),
            null,
            CoreRuntimeException::class,
        ];
    }

    /**
     * RFC 7519 §4.1.4, RFC 6750 §3.1
     */
    #[Test]
    public function itRefusesAnExpiredToken(): void
    {
        // Given
        $this->knows(self::PAYLOAD);

        // When
        try {
            $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now()->modify('+10 minutes'));
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            // Then
            static::assertSame('invalid_token', $exception->error);
            static::assertSame(401, $exception->statusCode);
            static::assertSame('The access token expired.', $exception->errorDescription);
            static::assertNull($exception->getPrevious());
        }
    }

    #[Test]
    public function itRefusesATokenOfAnotherTenant(): void
    {
        // Given
        $this->jws->knows(Fixtures::tenant('other', 'https://id.other.example'), self::TOKEN, self::PAYLOAD, [
            'typ' => 'at+jwt',
        ]);

        // Then
        $this->expectException(InvalidTokenException::class);

        // When
        $this->verifier->verify($this->tenant, self::TOKEN, Fixtures::now());
    }

    /**
     * @param array<string, string>|null $header
     */
    private function knows(string $payload, ?array $header = null): void
    {
        $this->jws->knows(
            $this->tenant,
            self::TOKEN,
            $payload,
            $header ?? [
                'typ' => 'at+jwt',
            ],
        );
    }

    /**
     * @param array<string, mixed> $changes
     */
    private static function with(array $changes): string
    {
        return json_encode($changes + json_decode(self::PAYLOAD, true, 8, JSON_THROW_ON_ERROR), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private static function without(string $claim): string
    {
        return self::withoutAll([$claim]);
    }

    /**
     * @param list<string> $claims
     */
    private static function withoutAll(array $claims): string
    {
        $payload = json_decode(self::PAYLOAD, true, 8, JSON_THROW_ON_ERROR);
        foreach ($claims as $claim) {
            unset($payload[$claim]);
        }

        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Architecture §4.6, Decision 0006
     */
    #[Test]
    #[DataProvider('provideValuesOfNoShape')]
    public function aValueOfAShapeTheProviderNeverWritesIsNotOne(string $value): void
    {
        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIsOrContains('not an access token issued by this provider');

        // When
        $this->verifier->verify($this->tenant, $value, Fixtures::now());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesOfNoShape(): iterable
    {
        yield 'nothing' => [''];
        yield 'a word' => ['the-opaque-token'];
        yield 'a drawn value with something appended' => [Secrets::draw() . 'x'];
        yield 'the digest of a value, which is not the value' => [DrawnSecret::digestOf(Secrets::draw())];
    }

    #[Test]
    public function aShapeWrittenAndReadBackByNobodyIsRefused(): void
    {
        // Given
        $verifier = new AccessTokenVerifier([], Shapes::served());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The provider writes access tokens in the "jwt" shape and nothing reads them back.');

        // When
        $verifier->verify($this->tenant, self::TOKEN, Fixtures::now());
    }

    #[Test]
    public function aVerifierOfAShapeNothingWritesIsRefused(): void
    {
        // Given
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $verifier = new AccessTokenVerifier(
            [
                new JwtAccessTokenVerifier($this->jws, $clients, Bindings::wired(), AuthorizationDetailTypes::served(), Subjects::sealedPerson()),
                new OpaqueAccessTokenVerifier($this->storedTokens, Subjects::publicKind()),
            ],
            new ServedAccessTokenShapes([new FakeAccessTokenIssuer('jwt')]),
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A verifier reads access tokens of the "opaque" shape back and nothing writes them; the wired shapes are jwt.');

        // When
        $verifier->verify($this->tenant, $this->opaque, Fixtures::now());
    }
}
