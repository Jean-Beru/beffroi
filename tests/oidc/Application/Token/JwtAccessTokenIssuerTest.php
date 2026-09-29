<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Oidc\Tests\Fixture\Grants;
use function array_keys;
use DateInterval;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Domain\Exchange\Actor;
use Heidi\Oidc\Domain\Exchange\MayAct;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\ClientAuthorization;
use Heidi\Oidc\Domain\Token\SubjectAuthorization;
use Heidi\Oidc\Domain\Token\TokenSignIn;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Heidi\Oidc\Tests\Fixture\Certificates;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use Heidi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

final class JwtAccessTokenIssuerTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private Jwts $jwts;

    private JwtAccessTokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->jwts = new Jwts($this->session->tenant);
        $this->issuer = new JwtAccessTokenIssuer($this->jwts->signer, Subjects::publicKind(), Algorithms::all(), new SymfonyUuidGenerator());
    }

    /**
     * Architecture §4.6: ten minutes from issuance, as a compact JWS.
     */
    #[Test]
    public function itMintsACompactJwsForTenMinutes(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token->value));
    }

    /**
     * RFC 9068 §2.1: header "typ" at+jwt, signed with the active key named by "kid". Verified by
     * jwt-library against the published JWKS, the way a resource server does.
     */
    #[Test]
    public function theHeaderNamesTheTypeAndTheActiveKey(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['header' => $header] = $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(
            [
                'typ' => 'at+jwt',
                'alg' => 'RS256',
                'kid' => $this->jwts->key->kid,
            ],
            $header,
        );
    }

    /**
     * RFC 9068 §2.2: "iss", "exp", "aud", "sub", "client_id", "iat", "jti"; §2.2.1: "auth_time", "amr";
     * §2.2.3: "scope" as RFC 8693 §4.2 writes it; "sid" of the session and "grant_id" of the
     * authorization code the token descends from (architecture §4.6).
     */
    #[Test]
    public function thePayloadCarriesTheClaimsOfRfc9068InOrder(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile', 'email']);
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code);
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'auth_time', 'acr', 'amr', 'scope', 'sid', 'grant_id'], array_keys($claims));
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['client_id']);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['iat']);
        static::assertIsString($claims['jti']);
        static::assertTrue(Uuid::isValid($claims['jti']));
        static::assertSame($this->session->authenticatedAt()->getTimestamp(), $claims['auth_time']);
        static::assertSame(['pwd'], $claims['amr']);
        static::assertSame('openid profile email', $claims['scope']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
        static::assertSame($code->grantId->toRfc4122(), $claims['grant_id']);
    }

    /**
     * RFC 9068 §2.2, RFC 6749 §4.4: a token a client holds for itself names that client in "sub" and says
     * nothing of a sign-in, there having been none: no "sid", no "auth_time", no "acr", no "amr".
     */
    #[Test]
    public function aTokenNobodySignedInForNamesTheClientAndCarriesNoSignIn(): void
    {
        // Given
        $client = Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'scope', 'grant_id'], array_keys($claims));
        static::assertSame('batch', $claims['sub']);
        static::assertSame('batch', $claims['client_id']);
        static::assertSame(Clients::CALENDAR, $claims['aud']);
        static::assertSame('invoices.read', $claims['scope']);
        static::assertSame($authorization->grantId->toRfc4122(), $claims['grant_id']);
    }

    /**
     * RFC 8693 §2.2.1, §4.1: a token somebody holds for its subject names the subject it was given and the
     * chain of actors that holds it, the most recent actor outermost, and carries the sign-in the token it
     * descends from named.
     */
    #[Test]
    public function aTokenExchangedForAnotherNamesItsSubjectAndWhoHoldsIt(): void
    {
        // Given
        $gateway = Clients::gateway($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $signIn = new TokenSignIn($this->session->id, AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()));
        $authorization = new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            $gateway,
            new Subject('alice-subject'),
            new Scopes([new Scope('invoices.read')]),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
            $signIn,
            new Actor(new Subject('gateway'), new Actor(new Subject('first-hop'))),
        );
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('gateway', $claims['client_id']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
        static::assertSame(
            [
                'sub' => 'gateway',
                'act' => [
                    'sub' => 'first-hop',
                ],
            ],
            $claims['act'],
        );
    }

    /**
     * RFC 8693 §1.3: an impersonation says nothing of anybody acting, which is what tells it from a
     * delegation.
     */
    #[Test]
    public function aTokenNobodyHoldsForItsSubjectCarriesNoActor(): void
    {
        // Given
        $gateway = Clients::gateway($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            $gateway,
            new Subject('alice-subject'),
            new Scopes([new Scope('invoices.read')]),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertArrayNotHasKey('act', $claims);
        static::assertArrayNotHasKey('sid', $claims);
    }

    /**
     * RFC 9396 §7: a token of a grant somebody agreed to details for carries the details of the response,
     * the array as it travelled and as an introspection renders it.
     */
    #[Test]
    public function aTokenOfAGrantWithDetailsCarriesThem(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details('acct-4711', ['read']);
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            authorizationDetails: $details,
        ));
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, $this->client->registration->clientId, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($details->toClaim(), $claims['authorization_details']);
    }

    /**
     * A grant nobody agreed to a detail for carries none, so the token says nothing of one rather than
     * saying it empty.
     */
    #[Test]
    public function aTokenOfAGrantWithoutDetailsCarriesNone(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, $this->client->registration->clientId, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertArrayNotHasKey('authorization_details', $claims);
    }

    /**
     * RFC 9396 §7: the token carries the details of the response and not the ones the grant stands on, so a
     * request that narrowed them gets a token that carries the subset it asked for.
     */
    #[Test]
    public function aTokenNarrowedToASubsetOfTheDetailsCarriesThatSubset(): void
    {
        // Given
        $granted = new AuthorizationDetails([
            AuthorizationDetailTypes::detail('acct-4711'),
            AuthorizationDetailTypes::detail('acct-0815'),
        ]);
        $narrowed = AuthorizationDetailTypes::details('acct-0815');
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), authorizationDetails: $granted),
            authorizationDetails: $narrowed,
        );
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, $this->client->registration->clientId, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($narrowed->toClaim(), $claims['authorization_details']);
    }

    /**
     * RFC 8693 §4.4: who may act for the subject of a token of this client, as its registration says it, so
     * that a resource server verifying the token offline reads the rule the provider applies.
     */
    #[Test]
    public function aTokenOfAClientThatNamesWhoMayActForItCarriesThatName(): void
    {
        // Given
        $gateway = Clients::gateway(
            $this->session->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            mayAct: new MayAct(new Subject('backend')),
        );
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $gateway,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(
            [
                'sub' => 'backend',
            ],
            $claims['may_act'],
        );
    }

    /**
     * RFC 8707 §2: the token is addressed to the resources the request asked it for, and "client_id"
     * goes on naming the client (RFC 9068 §2.2). One audience is written as a string and several as a
     * list (RFC 7519 §4.1.3).
     *
     * @param list<string> $resources
     * @param string|list<string> $audience
     */
    #[Test]
    #[DataProvider('provideAudiences')]
    public function theTokenIsAddressedToTheResourcesItWasAskedFor(array $resources, string|array $audience): void
    {
        // Given
        $client = Clients::public($this->session->tenant, resources: Clients::resources());
        $code = Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            resources: ResourceIndicators::of($resources),
        );
        $token = $this->issuer->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            Fixtures::now(),
        );

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($audience, $claims['aud']);
        static::assertSame('spa', $claims['client_id']);
    }

    /**
     * @return iterable<string, array{list<string>, string|list<string>}>
     */
    public static function provideAudiences(): iterable
    {
        yield 'one resource' => [[Clients::CALENDAR], Clients::CALENDAR];
        yield 'two resources' => [
            [Clients::CALENDAR, Clients::CONTACTS],
            [Clients::CALENDAR, Clients::CONTACTS],
        ];
    }

    /**
     * RFC 7519 §4.1.7: two tokens never share a "jti".
     */
    #[Test]
    public function twoTokensNeverShareAJti(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $first = $this->issuer->issue($authorization, Fixtures::now());
        $second = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertNotSame(
            $this->jwts->verify($first->value, 'spa', Fixtures::now())['claims']['jti'],
            $this->jwts->verify($second->value, 'spa', Fixtures::now())['claims']['jti'],
        );
    }

    /**
     * RFC 9068 §2.2.1: "acr" as the session satisfies it, two factors here, "amr" with every method.
     */
    #[Test]
    public function itWritesTheAuthenticationContextOfTheSession(): void
    {
        // Given
        $session = new AuthenticationSession(
            Uuid::v7(),
            $this->session->tenant,
            $this->session->user,
            Fixtures::now(),
            AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(
                new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD),
                Fixtures::now(),
            ),
            Fixtures::context(),
            Fixtures::now()->modify('+12 hours'),
        );
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $session,
            Fixtures::now(),
        ));
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame('2', $claims['acr']);
        static::assertSame(['pwd', 'otp', 'mfa'], $claims['amr']);
    }

    /**
     * RFC 6749 §6: the scope of a refresh response is the narrowed one.
     */
    #[Test]
    public function theScopeIsTheOneOfTheResponse(): void
    {
        // Given
        $authorization = UserAuthorization::fromRefreshToken(
            Grants::refreshToken(),
            Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']),
            new Scopes([new Scope('profile')]),
        );
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame('profile', $claims['scope']);
    }

    /**
     * Architecture §4.6: the lifetime is a choice, ten minutes by default.
     */
    #[Test]
    public function theLifetimeIsConfigurable(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            new DateInterval('PT1M'),
        );

        // When
        $token = $issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 minute'), $token->expiresAt);
        static::assertSame(60, $token->expiresIn());
    }

    /**
     * A token is refused once past its lifetime.
     */
    #[Test]
    public function aTokenIsRefusedOncePastItsLifetime(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            new DateInterval('PT1M'),
        )->issue(
            $authorization,
            Fixtures::now(),
        );

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+61 seconds'));
    }

    /**
     * RFC 9068 §4: "aud" is the client, so a token minted for one client fails the audience check of another.
     */
    #[Test]
    public function theAudienceIsTheClient(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($token->value, 'other', Fixtures::now());
    }

    /**
     * Architecture §4.6: the names asked for by "claims.userinfo" (OIDC Core §5.5) travel in the token
     * as "userinfo_claims", in the order given, so that UserInfo serves them from the token alone; those
     * of "claims.id_token" do not.
     */
    #[Test]
    public function itCarriesTheNamesOfTheClaimsAskedForFromUserInfo(): void
    {
        // Given
        $asked = ClaimsRequest::fromJson('{"userinfo":{"email":{"essential":true},"name":null},"id_token":{"picture":null}}');
        $token = $this->issuer->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                $this->client,
                $this->session,
                Fixtures::now(),
                claims: $asked,
            )),
            Fixtures::now(),
        );

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(
            ['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'auth_time', 'acr', 'amr', 'scope', 'userinfo_claims', 'sid', 'grant_id'],
            array_keys($claims),
        );
        static::assertSame(['email', 'name'], $claims['userinfo_claims']);
        static::assertStringContainsString('"userinfo_claims":["email","name"]', Jwts::rawPayload($token->value));
    }

    /**
     * RFC 8705 §3.1: a token issued on a request that proved a certificate carries the thumbprint of
     * that certificate in its "cnf" (RFC 7800 §3.1), which is what a resource server verifying the token
     * offline asks its caller to present again.
     */
    #[Test]
    public function itBindsTheTokenToWhatTheClientProved(): void
    {
        // Given
        $certificate = Certificates::client();
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('the-code', $this->client, $this->session, Fixtures::now()),
            CertificateConfirmation::ofCertificate($certificate),
        );

        // When
        $claims = $this->jwts->verify($this->issuer->issue($authorization, Fixtures::now())->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(
            [
                'x5t#S256' => $certificate->x5tS256(),
            ],
            $claims['cnf'],
        );
    }

    /**
     * A client that proved nothing but who it is gets a bearer token, and a token that says so by
     * carrying no confirmation at all (RFC 6750 §2).
     */
    #[Test]
    public function aTokenOfAClientThatProvedNoKeyCarriesNoConfirmation(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $claims = $this->jwts->verify($this->issuer->issue($authorization, Fixtures::now())->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertArrayNotHasKey('cnf', $claims);
    }

    /**
     * Nothing is written when the request asked for the ID token only.
     */
    #[Test]
    public function itCarriesNoUserinfoClaimsWhenTheRequestAskedForTheIdTokenOnly(): void
    {
        // Given
        $idTokenOnly = ClaimsRequest::fromJson('{"id_token":{"picture":null}}');
        $token = $this->issuer->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                $this->client,
                $this->session,
                Fixtures::now(),
                claims: $idTokenOnly,
            )),
            Fixtures::now(),
        );

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertArrayNotHasKey('userinfo_claims', $claims);
    }
}
