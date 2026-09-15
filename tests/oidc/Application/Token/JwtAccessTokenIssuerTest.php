<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use function array_keys;
use DateInterval;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
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

    private Jwts $jwts;

    private JwtAccessTokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->jwts = new Jwts($this->session->tenant);
        $this->issuer = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver());
    }

    /**
     * RFC 9068 §2.1: header "typ" at+jwt, signed with the active key named by "kid"; §2.2: "iss", "exp",
     * "aud", "sub", "client_id", "iat", "jti"; §2.2.1: "auth_time", "amr"; §2.2.3: "scope" as RFC 8693
     * §4.2 writes it; "sid" of the session (architecture §4.6). Ten minutes. Verified by jwt-library
     * against the published JWKS, the way a resource server does.
     */
    #[Test]
    public function itMintsAnAtJwtVerifiableAgainstThePublishedJwks(): void
    {
        $client = Clients::public($this->session->tenant);
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $client, $this->session, Fixtures::now(), ['openid', 'profile', 'email']));

        $token = $this->issuer->issue($authorization, Fixtures::now());

        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
        ['header' => $header, 'claims' => $claims] = $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'));
        static::assertSame([
            'typ' => 'at+jwt',
            'alg' => 'RS256',
            'kid' => $this->jwts->key->kid,
        ], $header);
        static::assertSame(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'auth_time', 'amr', 'scope', 'sid'], array_keys($claims));
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
    }

    /**
     * RFC 7519 §4.1.7: two tokens never share a "jti"; RFC 9068 §2.2.1: "acr" when the session has one;
     * RFC 6749 §6: the scope of a refresh response is the narrowed one.
     */
    #[Test]
    public function itWritesTheAuthenticationContextAndTheScopesOfTheResponse(): void
    {
        $client = Clients::public($this->session->tenant);
        $session = new AuthenticationSession(Uuid::v7(), $this->session->tenant, $this->session->user, Fixtures::now(), AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::now()), 'urn:acme:mfa', Fixtures::context(), Fixtures::now()->modify('+12 hours'));
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $client, $session, Fixtures::now(), null, ['openid', 'profile']), [new Scope('profile')]);

        $first = $this->issuer->issue($authorization, Fixtures::now());
        $second = $this->issuer->issue($authorization, Fixtures::now());

        $claims = $this->jwts->verify($first->value, 'spa', Fixtures::now())['claims'];
        static::assertSame('urn:acme:mfa', $claims['acr']);
        static::assertSame(['pwd', 'otp'], $claims['amr']);
        static::assertSame('profile', $claims['scope']);
        static::assertNotSame($claims['jti'], $this->jwts->verify($second->value, 'spa', Fixtures::now())['claims']['jti']);
    }

    /**
     * Architecture §4.6: the lifetime is a choice, ten minutes by default; a token is refused once past it.
     */
    #[Test]
    public function theLifetimeIsConfigurable(): void
    {
        $client = Clients::public($this->session->tenant);
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $client, $this->session, Fixtures::now()));
        $issuer = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new DateInterval('PT1M'));

        $token = $issuer->issue($authorization, Fixtures::now());

        static::assertEquals(Fixtures::now()->modify('+1 minute'), $token->expiresAt);
        static::assertSame(60, $token->expiresIn());
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token->value));
        $this->expectException(InvalidClaimException::class);
        $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+61 seconds'));
    }

    /**
     * RFC 9068 §4: "aud" is the client, so a token minted for one client fails the audience check of another.
     */
    #[Test]
    public function theAudienceIsTheClient(): void
    {
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', Clients::public($this->session->tenant), $this->session, Fixtures::now()));

        $token = $this->issuer->issue($authorization, Fixtures::now());

        $this->expectException(InvalidClaimException::class);
        $this->jwts->verify($token->value, 'other', Fixtures::now());
    }

    /**
     * Architecture §4.6: the names asked for by "claims.userinfo" (OIDC Core §5.5) travel in the token
     * as "userinfo_claims", in the order given, so that UserInfo serves them from the token alone; those
     * of "claims.id_token" do not, and nothing is written when nothing was asked, or when the request
     * asked for the ID token only.
     */
    #[Test]
    public function itCarriesTheNamesOfTheClaimsAskedForFromUserInfo(): void
    {
        $client = Clients::public($this->session->tenant);
        $asked = ClaimsRequest::fromJson('{"userinfo":{"email":{"essential":true},"name":null},"id_token":{"picture":null}}');
        $idTokenOnly = ClaimsRequest::fromJson('{"id_token":{"picture":null}}');

        $with = $this->issuer->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $client, $this->session, Fixtures::now(), claims: $asked)), Fixtures::now());
        $without = $this->issuer->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $client, $this->session, Fixtures::now(), claims: $idTokenOnly)), Fixtures::now());

        $claims = $this->jwts->verify($with->value, 'spa', Fixtures::now())['claims'];
        static::assertSame(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'auth_time', 'amr', 'scope', 'userinfo_claims', 'sid'], array_keys($claims));
        static::assertSame(['email', 'name'], $claims['userinfo_claims']);
        static::assertStringContainsString('"userinfo_claims":["email","name"]', Jwts::rawPayload($with->value));
        static::assertArrayNotHasKey('userinfo_claims', $this->jwts->verify($without->value, 'spa', Fixtures::now())['claims']);
    }
}
