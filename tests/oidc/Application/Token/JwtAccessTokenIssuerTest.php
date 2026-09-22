<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use function array_keys;
use DateInterval;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Tests\Fixture\Certificates;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
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
        $this->issuer = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all());
    }

    /**
     * Architecture §4.6: ten minutes from issuance, as a compact JWS.
     */
    #[Test]
    public function itMintsACompactJwsForTenMinutes(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));

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
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));
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
        $authorization = GrantedAuthorization::fromAuthorizationCode($code);
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
     * RFC 7519 §4.1.7: two tokens never share a "jti".
     */
    #[Test]
    public function twoTokensNeverShareAJti(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));

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
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $session, Fixtures::now()));
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
        $authorization = GrantedAuthorization::fromRefreshToken(
            Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']),
            [new Scope('profile')],
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
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));
        $issuer = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT1M'));

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
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));
        $token = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), Algorithms::all(), new DateInterval('PT1M'))->issue(
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
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));
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
            GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), claims: $asked)),
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
        $authorization = GrantedAuthorization::fromAuthorizationCode(
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
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));

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
            GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), claims: $idTokenOnly)),
            Fixtures::now(),
        );

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertArrayNotHasKey('userinfo_claims', $claims);
    }
}
