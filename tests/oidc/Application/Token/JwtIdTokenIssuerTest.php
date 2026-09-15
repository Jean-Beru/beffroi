<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use function array_keys;
use function base64_encode;
use DateInterval;
use function hash;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsVerifier;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function strtr;
use function substr;
use Symfony\Component\Uid\Uuid;

final class JwtIdTokenIssuerTest extends TestCase
{
    private const string ACCESS_TOKEN = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';

    private AuthenticationSession $session;

    private Client $client;

    private Jwts $jwts;

    private JwtIdTokenIssuer $issuer;

    private AccessToken $accessToken;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->jwts = new Jwts($this->session->tenant);
        $this->issuer = new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider());
        $this->accessToken = new AccessToken(self::ACCESS_TOKEN, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * OIDC Core §2: "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp"; §3.1.3.6:
     * "at_hash", cross-checked here with an independent computation and with the value of appendix A.3;
     * "sid" of the session (architecture §4.6). RS256 with the active key, "kid" in the header, no "typ".
     * Ten minutes. Verified by jwt-library against the published JWKS, the way oidc_login does.
     */
    #[Test]
    public function itMintsAnIdTokenVerifiableAgainstThePublishedJwks(): void
    {
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile']));

        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        ['header' => $header, 'claims' => $claims] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));
        static::assertSame([
            'alg' => 'RS256',
            'kid' => $this->jwts->key->kid,
        ], $header);
        static::assertSame(['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'amr', 'azp', 'at_hash', 'sid'], array_keys($claims));
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['iat']);
        static::assertSame($this->session->authenticatedAt()->getTimestamp(), $claims['auth_time']);
        static::assertSame('n-0S6_WzA2Mj', $claims['nonce']);
        static::assertSame(['pwd'], $claims['amr']);
        static::assertSame('spa', $claims['azp']);
        static::assertSame(rtrim(strtr(base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 0, 16)), '+/', '-_'), '='), $claims['at_hash']);
        static::assertSame('77QmUPtjPfzWtF2AnpK9RQ', $claims['at_hash']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
    }

    /**
     * OIDC Core §12.2: on a refresh, no "nonce"; the authentication described is the original one, as the
     * refresh token carried it, "acr" included when there is one.
     */
    #[Test]
    public function onARefreshThereIsNoNonceAndTheOriginalAuthenticationIsDescribed(): void
    {
        $session = new AuthenticationSession(Uuid::v7(), $this->session->tenant, $this->session->user, Fixtures::now(), AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::now()), 'urn:acme:mfa', Fixtures::context(), Fixtures::now()->modify('+12 hours'));
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $session, Fixtures::now()), null);
        $later = Fixtures::now()->modify('+20 days');

        $idToken = $this->issuer->issue($authorization, $this->accessToken, $later);

        $claims = $this->jwts->verify($idToken, 'spa', $later)['claims'];
        static::assertArrayNotHasKey('nonce', $claims);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['auth_time']);
        static::assertSame($later->getTimestamp(), $claims['iat']);
        static::assertSame('urn:acme:mfa', $claims['acr']);
        static::assertSame(['pwd', 'otp'], $claims['amr']);
        static::assertSame(['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'acr', 'amr', 'azp', 'at_hash', 'sid'], array_keys($claims));
    }

    /**
     * OIDC Core §5.5: the claims of "claims.id_token" are in the ID token, those of "claims.userinfo" and
     * of the scopes are not (§5.4: they belong to UserInfo); §5.1: "email_verified" is a JSON boolean on
     * the wire; a claim the user has no value for is absent.
     */
    #[Test]
    public function itAddsTheClaimsRequestedForTheIdTokenAndNoOther(): void
    {
        $user = Fixtures::user($this->session->tenant);
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
        $user->updateProfile(new Profile(givenName: 'Alice'), Fixtures::now());
        $session = Fixtures::session($user);
        $claims = ClaimsRequest::fromJson('{"id_token":{"email":null,"email_verified":{"essential":true},"family_name":null},"userinfo":{"given_name":null}}');
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $session, Fixtures::now(), ['openid', 'profile', 'email'], claims: $claims));

        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        $decoded = $this->jwts->verify($idToken, 'spa', Fixtures::now())['claims'];
        static::assertSame('alice@acme.example', $decoded['email']);
        static::assertTrue($decoded['email_verified']);
        static::assertArrayNotHasKey('family_name', $decoded);
        static::assertArrayNotHasKey('given_name', $decoded);
        static::assertArrayNotHasKey('updated_at', $decoded);
        static::assertSame(['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'amr', 'azp', 'at_hash', 'sid', 'email', 'email_verified'], array_keys($decoded));
        static::assertStringContainsString('"email_verified":true', Jwts::rawPayload($idToken));
    }

    /**
     * Without a claims request, or with one that asks nothing for the ID token, the provider is not
     * consulted at all.
     */
    #[Test]
    public function theProviderIsNotAskedWhenNothingIsRequestedForTheIdToken(): void
    {
        $provider = new class() implements ClaimsProviderInterface {
            public int $calls = 0;

            public function claims(User $user, array $scopes, array $requested): array
            {
                ++$this->calls;

                return [];
            }
        };
        $issuer = new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), $provider);

        $issuer->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('a', $this->client, $this->session, Fixtures::now())), $this->accessToken, Fixtures::now());
        $issuer->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('b', $this->client, $this->session, Fixtures::now(), claims: ClaimsRequest::fromJson('{"userinfo":{"name":null}}'))), $this->accessToken, Fixtures::now());

        static::assertSame(0, $provider->calls);
    }

    /**
     * A claims provider answers about the user, not about the protocol: "iss", "sub", "aud" and the rest
     * stay what the issuer wrote, whatever comes back under the same names.
     */
    #[Test]
    public function aClaimsProviderCannotOverrideTheProtocolClaims(): void
    {
        $provider = new class() implements ClaimsProviderInterface {
            public function claims(User $user, array $scopes, array $requested): array
            {
                return [
                    'sub' => 'mallory',
                    'aud' => 'other',
                    'exp' => 0,
                    'name' => 'Alice',
                ];
            }
        };
        $issuer = new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), $provider);
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), claims: ClaimsRequest::fromJson('{"id_token":{"name":null}}')));

        $claims = $this->jwts->verify($issuer->issue($authorization, $this->accessToken, Fixtures::now()), 'spa', Fixtures::now())['claims'];

        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame('Alice', $claims['name']);
    }

    /**
     * Architecture §4.6: the lifetime is a choice, ten minutes by default. OIDC Core §3.1.2.1: the same
     * token, given back as id_token_hint, is one this provider recognizes (the verifier of issue #6 reads
     * what this issuer writes).
     */
    #[Test]
    public function theLifetimeIsConfigurableAndTheTokenServesAsAHint(): void
    {
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));
        $issuer = new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider(), new DateInterval('PT1H'));

        $idToken = $issuer->issue($authorization, $this->accessToken, Fixtures::now());

        static::assertSame(Fixtures::now()->modify('+1 hour')->getTimestamp(), $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+59 minutes'))['claims']['exp']);
        static::assertSame('alice-subject', new IdTokenHintVerifier(new JwtFrameworkJwsVerifier($this->jwts->keys))->verify($this->client, $idToken)->value);
        $this->expectException(InvalidClaimException::class);
        $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+61 minutes'));
    }

    /**
     * OIDC Core §3.1.3.7 step 3: a token minted for one client fails the audience check of another; the
     * scopes of the response do not change the ID token.
     */
    #[Test]
    public function theAudienceIsTheClient(): void
    {
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']), [new Scope('openid')]);

        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        $this->expectException(InvalidClaimException::class);
        $this->jwts->verify($idToken, 'other', Fixtures::now());
    }
}
