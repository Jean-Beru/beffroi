<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Tests\Fixture\AccessTokenShapes;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

final class AccessTokenVerifierTest extends TestCase
{
    private const string TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2lkLmFjbWUuZXhhbXBsZSJ9.c2lnbmF0dXJl';

    /**
     * A payload as JwtAccessTokenIssuer writes it, valid for ten minutes from Fixtures::now().
     */
    private const string PAYLOAD = '{"iss":"https://id.acme.example","exp":1789467000,"aud":"spa","sub":"alice-subject","client_id":"spa","iat":1789466400,"jti":"6f1c2b7e-1d2a-4c3b-8e9f-0a1b2c3d4e5f","auth_time":1789466400,"acr":"1","amr":["pwd"],"scope":"openid profile","sid":"01997b9e-0000-7000-8000-000000000000","grant_id":"01997b9e-0000-7000-8000-00000000000a"}';

    private Tenant $tenant;

    private Client $client;

    private FakeJwsVerifier $jws;

    private InMemoryAccessTokenRepository $storedTokens;

    private AccessTokenVerifier $verifier;

    /**
     * An opaque token of this provider is one it drew (architecture §4.6); a value of another shape was
     * not issued here, which the verifier says without reading any store.
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
        $this->opaque = DrawnSecret::draw();
        $this->verifier = AccessTokenShapes::verifier($this->jws, $clients, $this->storedTokens, new PublicSubjectIdentifierResolver());
    }

    /**
     * RFC 9068 §4: signature, "typ" at+jwt, "iss", "exp", "aud"; §2.2: "client_id" names the client,
     * "sub" the subject; §2.2.3: "scope" as RFC 8693 §4.2 writes it; architecture §4.6:
     * "userinfo_claims" the names asked for by OIDC Core §5.5. Read from a token the issuer really minted
     * and the bridge of the core really verified.
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
        $minted = new JwtAccessTokenIssuer($jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all())->issue(
            GrantedAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            Fixtures::now(),
        );
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $verifier = AccessTokenShapes::verifier(
            new JwtLibraryJwsVerifier($jwts->keys, Algorithms::all()),
            $clients,
            $this->storedTokens,
            new PublicSubjectIdentifierResolver(),
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
        static::assertTrue($session->id->equals($token->sessionId));
        static::assertEquals($session->authenticatedAt(), $token->authentication->authenticatedAt);
        static::assertSame(['pwd'], $token->authentication->methods);
        static::assertSame('1', $token->authentication->contextClass);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * Architecture §4.6: an opaque token is the record the repository keeps under its hash, read the
     * way the JWT claims are, with "sub" through the same resolver that names the subject in a JWT.
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
        $this->storedTokens->keep($record);

        // When
        $token = $this->verifier->verify($this->tenant, $this->opaque, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($this->client, $token->client);
        static::assertSame('alice-subject', (string) $token->subject);
        static::assertSame(['openid', 'email'], $token->scopes?->values());
        static::assertSame(['name', 'picture'], $token->userinfoClaims);
        static::assertTrue($record->grantId->equals($token->grantId));
        static::assertTrue($session->id->equals($token->sessionId));
        static::assertEquals($session->authenticatedAt(), $token->authentication->authenticatedAt);
        static::assertSame(['pwd'], $token->authentication->methods);
        static::assertSame('1', $token->authentication->contextClass);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * RFC 8707 §2: an opaque token says who it is addressed to exactly as the self-contained shape
     * does, so that a resource server learns the same thing from the introspection of one as from the
     * "aud" of the other.
     *
     * @param list<string>|null $resources
     * @param list<string> $audience
     */
    #[Test]
    #[DataProvider('provideStoredResources')]
    public function itReadsWhoAnOpaqueTokenIsAddressedTo(?array $resources, array $audience): void
    {
        // Given
        $this->storedTokens->keep(Tokens::storedAccessToken(
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

    /**
     * A record without claims asked for by name is a token that asked for none.
     */
    #[Test]
    public function anOpaqueTokenWithoutAClaimsRequestAskedForNoClaimByName(): void
    {
        // Given
        $this->storedTokens->keep(Tokens::storedAccessToken(
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
     * RFC 6750 §3.1: a value the repository does not know, in this tenant, is not a token of the provider.
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
            $test->storedTokens->keep(Tokens::storedAccessToken(
                'another-token',
                $test->client,
                Fixtures::session(Fixtures::user($test->tenant)),
                Fixtures::now(),
            ));
        }];
        yield 'a record of another tenant' => [static function (self $test): void {
            $other = Fixtures::tenant('other', 'https://id.other.example');
            $test->storedTokens->keep(Tokens::storedAccessToken(
                $test->opaque,
                Clients::public($other),
                Fixtures::session(Fixtures::user($other)),
                Fixtures::now(),
            ));
        }];
    }

    /**
     * RFC 7519 §4.1.4 applied to the record: the second of expiry included is too late, and the client
     * is told to refresh.
     */
    #[Test]
    public function itRefusesAnExpiredOpaqueToken(): void
    {
        // Given
        $this->storedTokens->keep(Tokens::storedAccessToken(
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
     * RFC 7519 §4.1.3: "aud" is a string or a list; RFC 9068 §2.2.3: no "scope" is no scope; architecture
     * §4.6: no "userinfo_claims" is no claim asked for by name.
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
     * RFC 6750 §3.1: whatever is not an access token of this provider is invalid_token, 401, with one
     * description and the cause kept for the logs; RFC 9068 §4 lists what is checked: the signature, the
     * "typ" header, "iss", "exp", "aud". RFC 8725 §3.11: "aud" is checked against the client the token
     * names and that client is one of the tenant's.
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
                'amr' => [['pwd']],
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
    }

    /**
     * RFC 7519 §4.1.4: the current time must be before "exp", the second of "exp" included is too late;
     * RFC 6750 §3.1: still invalid_token, with a description that tells the client to refresh.
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

    /**
     * The tenant is the one the token was verified for: a token of another tenant does not verify
     * against the keys of this one, and it is not read.
     */
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
     * @param array<string, string>|null $header null for the header of a real access token
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
        $claims = json_decode(self::PAYLOAD, true, 8, JSON_THROW_ON_ERROR);
        unset($claims[$claim]);

        return json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Architecture §4.6 and decision 0006: a value of a shape this provider never writes is refused
     * before any store is read. The shapes recognise what they write, so nothing here reads a token to
     * guess its kind, and a value that is neither a compact JWS nor one drawn here is none of ours.
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
        yield 'a drawn value with something appended' => [DrawnSecret::draw() . 'x'];
        yield 'the digest of a value, which is not the value' => [DrawnSecret::digestOf(DrawnSecret::draw())];
    }
}
