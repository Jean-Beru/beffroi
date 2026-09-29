<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Tests\Fixture\Grants;
use function array_keys;
use function base64_encode;
use DateInterval;
use function explode;
use function hash;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientPresentation;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Tests\Fixture\ClientEncryption;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function strtr;
use function substr;
use Symfony\Component\Uid\Uuid;
use Heidi\Oidc\Tests\Fixture\Subjects;
use Heidi\Oidc\Tests\Fixture\Shapes;

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
        $this->issuer = new JwtIdTokenIssuer($this->jwts->documents, Subjects::publicKind(), new StandardClaimsProvider(), Algorithms::all());
        $this->accessToken = new AccessToken(self::ACCESS_TOKEN, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * OIDC Core §2: RS256 with the active key, "kid" in the header, no "typ". Verified by jwt-library
     * against the published JWKS, the way oidc_login does.
     */
    #[Test]
    public function theHeaderNamesTheActiveKeyAndNoType(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());

        // When
        ['header' => $header] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(
            [
                'alg' => 'RS256',
                'kid' => $this->jwts->key->kid,
            ],
            $header,
        );
    }

    /**
     * OIDC Core §2: "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp"; "sid" of the
     * session (architecture §4.6). Ten minutes.
     */
    #[Test]
    public function thePayloadCarriesTheClaimsOfOidcCoreInOrder(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'at_hash', 'sid'], array_keys($claims));
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['iat']);
        static::assertSame($this->session->authenticatedAt()->getTimestamp(), $claims['auth_time']);
        static::assertSame('n-0S6_WzA2Mj', $claims['nonce']);
        static::assertSame(['pwd'], $claims['amr']);
        static::assertSame('spa', $claims['azp']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
    }

    /**
     * Front-Channel Logout 1.0 §3 and Back-Channel Logout 1.0 §2.1: an OP that announces
     * frontchannel_logout_session_supported or backchannel_logout_session_supported puts "sid" in the ID
     * tokens it issues, and this one announces both as soon as it serves the channel (architecture §4.8).
     * What a client registers for itself, frontchannel_logout_session_required and
     * backchannel_logout_session_required, governs its logout URI (Front-Channel Logout 1.0 §2) and its
     * logout token (Back-Channel Logout 1.0 §2.2), never its ID token.
     *
     * @param callable(self): Client $client
     */
    #[Test]
    #[DataProvider('provideClientsOfEveryLogoutRegistration')]
    public function theSessionIsNamedInTheIdTokenOfEveryClient(callable $client): void
    {
        // Given
        $this->client = $client($this);
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
    }

    /**
     * @return iterable<string, array{callable(self): Client}>
     */
    public static function provideClientsOfEveryLogoutRegistration(): iterable
    {
        yield 'no logout channel at all' => [static fn (self $test): Client => Clients::public($test->session->tenant)];
        yield 'a front-channel URI that needs the session' => [
            static fn (self $test): Client => Clients::withFrontChannelLogout($test->session->tenant, sessionRequired: true),
        ];
        yield 'a front-channel URI that does not' => [static fn (self $test): Client => Clients::withFrontChannelLogout($test->session->tenant)];
        yield 'a back-channel URI' => [static fn (self $test): Client => Clients::withBackChannelLogout($test->session->tenant)];
    }

    /**
     * OIDC Core §3.1.3.6: "at_hash", cross-checked with an independent computation and with the value
     * of appendix A.3.
     */
    #[Test]
    public function theAtHashIsTheLeftHalfOfTheSha256OfTheAccessToken(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());

        // When
        $claims = $this->jwts->verify($idToken, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(rtrim(strtr(base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 0, 16)), '+/', '-_'), '='), $claims['at_hash']);
        static::assertSame('77QmUPtjPfzWtF2AnpK9RQ', $claims['at_hash']);
    }

    /**
     * OIDC Core §12.2: on a refresh, no "nonce"; the authentication described is the original one, as the
     * refresh token carried it, "acr" included.
     */
    #[Test]
    public function onARefreshThereIsNoNonceAndTheOriginalAuthenticationIsDescribed(): void
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
        $authorization = UserAuthorization::fromRefreshToken(
            Grants::refreshToken(),
            Tokens::refreshToken('previous', $this->client, $session, Fixtures::now()),
            null,
        );
        $later = Fixtures::now()->modify('+20 days');
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $later);

        // When
        $claims = $this->jwts->verify($idToken, 'spa', $later)['claims'];

        // Then
        static::assertSame(['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'acr', 'amr', 'azp', 'at_hash', 'sid'], array_keys($claims));
        static::assertArrayNotHasKey('nonce', $claims);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['auth_time']);
        static::assertSame($later->getTimestamp(), $claims['iat']);
        static::assertSame('2', $claims['acr']);
        static::assertSame(['pwd', 'otp', 'mfa'], $claims['amr']);
    }

    /**
     * OIDC Core §5.5: the claims of "claims.id_token" are in the ID token, those of "claims.userinfo" and
     * of the scopes are not (§5.4: they belong to UserInfo); a claim the user has no value for is absent.
     */
    #[Test]
    public function itAddsTheClaimsRequestedForTheIdTokenAndNoOther(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationWithRequestedClaims(), $this->accessToken, Fixtures::now());

        // When
        $decoded = $this->jwts->verify($idToken, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(
            ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'at_hash', 'sid', 'email', 'email_verified'],
            array_keys($decoded),
        );
        static::assertSame('alice@acme.example', $decoded['email']);
        static::assertArrayNotHasKey('family_name', $decoded);
        static::assertArrayNotHasKey('given_name', $decoded);
        static::assertArrayNotHasKey('updated_at', $decoded);
    }

    /**
     * OIDC Core §5.1: "email_verified" is a JSON boolean on the wire.
     */
    #[Test]
    public function theVerificationFlagIsAJsonBooleanOnTheWire(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationWithRequestedClaims(), $this->accessToken, Fixtures::now());

        // When
        $decoded = $this->jwts->verify($idToken, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertTrue($decoded['email_verified']);
        static::assertStringContainsString('"email_verified":true', Jwts::rawPayload($idToken));
    }

    /**
     * Without a claims request, or with one that asks nothing for the ID token, the provider is not
     * consulted at all.
     */
    #[Test]
    #[DataProvider('provideRequestsWithoutIdTokenClaims')]
    public function theProviderIsNotAskedWhenNothingIsRequestedForTheIdToken(?ClaimsRequest $claims): void
    {
        // Given
        $provider = new class() implements ClaimsProviderInterface {
            public int $calls = 0;

            public function claims(User $user, ?Scopes $scopes, array $requested): array
            {
                ++$this->calls;

                return [];
            }

            public function supportedScopes(): array
            {
                return [];
            }

            public function supportedClaims(): array
            {
                return [];
            }
        };
        $issuer = new JwtIdTokenIssuer($this->jwts->documents, Subjects::publicKind(), $provider, Algorithms::all());

        // When
        $issuer->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                $this->client,
                $this->session,
                Fixtures::now(),
                claims: $claims,
            )),
            $this->accessToken,
            Fixtures::now(),
        );

        // Then
        static::assertSame(0, $provider->calls);
    }

    /**
     * @return iterable<string, array{?ClaimsRequest}>
     */
    public static function provideRequestsWithoutIdTokenClaims(): iterable
    {
        yield 'no claims request' => [null];
        yield 'userinfo claims only' => [ClaimsRequest::fromJson('{"userinfo":{"name":null}}')];
    }

    /**
     * A claims provider answers about the user, not about the protocol: "iss", "sub", "aud" and the rest
     * stay what the issuer wrote, whatever comes back under the same names.
     */
    #[Test]
    public function aClaimsProviderCannotOverrideTheProtocolClaims(): void
    {
        // Given
        $provider = new class() implements ClaimsProviderInterface {
            public function claims(User $user, ?Scopes $scopes, array $requested): array
            {
                return [
                    'sub' => 'mallory',
                    'aud' => 'other',
                    'exp' => 0,
                    'name' => 'Alice',
                ];
            }

            public function supportedScopes(): array
            {
                return [];
            }

            public function supportedClaims(): array
            {
                return ['name'];
            }
        };
        $issuer = new JwtIdTokenIssuer($this->jwts->documents, Subjects::publicKind(), $provider, Algorithms::all());
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            claims: ClaimsRequest::fromJson('{"id_token":{"name":null}}'),
        ));

        // When
        $claims = $this->jwts->verify($issuer->issue($authorization, $this->accessToken, Fixtures::now()), 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame('Alice', $claims['name']);
    }

    /**
     * Architecture §4.6: the lifetime is a choice, ten minutes by default.
     */
    #[Test]
    public function theLifetimeIsConfigurable(): void
    {
        // Given
        $issuer = new JwtIdTokenIssuer(
            $this->jwts->documents,
            Subjects::publicKind(),
            new StandardClaimsProvider(),
            Algorithms::all(),
            new DateInterval('PT1H'),
        );
        $idToken = $issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());

        // When
        $claims = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+59 minutes'))['claims'];

        // Then
        static::assertSame(Fixtures::now()->modify('+1 hour')->getTimestamp(), $claims['exp']);
    }

    #[Test]
    public function aTokenIsRefusedOncePastItsLifetime(): void
    {
        // Given
        $issuer = new JwtIdTokenIssuer(
            $this->jwts->documents,
            Subjects::publicKind(),
            new StandardClaimsProvider(),
            Algorithms::all(),
            new DateInterval('PT1H'),
        );
        $idToken = $issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+61 minutes'));
    }

    /**
     * OIDC Core §3.1.2.1: the same token, given back as id_token_hint, is one this provider recognizes
     * (the verifier of issue #6 reads what this issuer writes).
     */
    #[Test]
    public function theTokenServesAsAnIdTokenHint(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, Fixtures::now());
        $verifier = new IdTokenHintVerifier(new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()));

        // When
        $subject = $verifier->verify($this->client, $idToken);

        // Then
        static::assertSame('alice-subject', $subject->value);
    }

    /**
     * OIDC Core §3.1.3.7 step 3: a token minted for one client fails the audience check of another; the
     * scopes of the response do not change the ID token.
     */
    #[Test]
    public function theAudienceIsTheClient(): void
    {
        // Given
        $authorization = UserAuthorization::fromRefreshToken(
            Grants::refreshToken(),
            Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']),
            new Scopes([new Scope('openid')]),
        );
        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($idToken, 'other', Fixtures::now());
    }

    /**
     * OIDC Registration §2: a tenant that holds one key per algorithm signs the ID token of a client with
     * the algorithm that client registered, and the JWK Set carries the key of each.
     */
    #[Test]
    public function aClientGetsItsIdTokenSignedWithTheAlgorithmItRegistered(): void
    {
        // Given
        $es256Key = $this->jwts->activate(Algorithms::es256());
        $client = new Client(
            $this->session->tenant,
            new ClientRegistration(
                'spa',
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                idToken: ResponseFormat::signed(Algorithms::es256()),
            ),
        );
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            ['openid'],
        ));

        // When
        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        // Then
        ['header' => $header] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));
        static::assertSame(
            [
                'alg' => 'ES256',
                'kid' => $es256Key->kid,
            ],
            $header,
        );
    }

    /**
     * OIDC Core §3.1.3.6: the "at_hash" halves the digest the "alg" names, so two algorithms of the same
     * digest agree on it and the ID token of a client is readable whichever key signed it.
     */
    #[Test]
    public function theAccessTokenHashFollowsTheAlgorithmThatSigns(): void
    {
        // Given
        $this->jwts->activate(Algorithms::edDsa());
        $client = new Client(
            $this->session->tenant,
            new ClientRegistration(
                'spa',
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                idToken: ResponseFormat::signed(Algorithms::edDsa()),
            ),
        );
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            ['openid'],
        ));

        // When
        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        // Then
        ['claims' => $claims] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));
        static::assertSame(self::leftHalf(hash('sha512', self::ACCESS_TOKEN, true)), $claims['at_hash']);
    }

    private static function leftHalf(string $digest): string
    {
        return rtrim(strtr(base64_encode(substr($digest, 0, 32)), '+/', '-_'), '=');
    }

    /**
     * The acceptance of issue #165: a client that registered an encryption receives a JWE it opens with
     * its own private key, and what it finds inside is the ID token signed by the tenant, which verifies
     * against the published JWK Set exactly as an unencrypted one does.
     */
    #[Test]
    public function aClientThatRegisteredAnEncryptionReceivesAJweItOpens(): void
    {
        // Given
        $client = Clients::encryptedFor($this->session->tenant, idToken: ResponseFormat::signed(null, ClientEncryption::registration()));
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            ['openid'],
        ));

        // When
        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        // Then
        ['header' => $header, 'payload' => $signed] = ClientEncryption::open($idToken);
        static::assertSame('ECDH-ES+A256KW', $header['alg']);
        static::assertSame('A256GCM', $header['enc']);
        static::assertSame(ClientEncryption::KEY_ID, $header['kid']);
        // RFC 7519 §5.2: the payload of the JWE says it is itself a JWT
        static::assertSame('JWT', $header['cty']);
        ['claims' => $claims] = $this->jwts->verify($signed, 'encrypted-client', Fixtures::now()->modify('+9 minutes'));
        static::assertSame('alice-subject', $claims['sub']);
    }

    /**
     * The signature is inside and not outside (OIDC Core §16.14): the client that registered an encryption
     * receives one token and not two, and nothing of the ID token is readable before the JWE is opened.
     */
    #[Test]
    public function anEncryptedIdTokenIsNotAJwsAnyoneCanRead(): void
    {
        // Given
        $client = Clients::encryptedFor($this->session->tenant, idToken: ResponseFormat::signed(null, ClientEncryption::registration()));
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            ['openid'],
        ));

        // When
        $idToken = $this->issuer->issue($authorization, $this->accessToken, Fixtures::now());

        // Then
        static::assertCount(5, explode('.', $idToken));
        static::assertStringNotContainsString('alice-subject', $idToken);
    }

    private function authorizationFromCode(): UserAuthorization
    {
        return UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'profile'],
        ));
    }

    /**
     * Alice with a verified email and a given name, asking "email", "email_verified" and "family_name"
     * for the ID token and "given_name" for UserInfo.
     */
    private function authorizationWithRequestedClaims(): UserAuthorization
    {
        $user = Fixtures::user($this->session->tenant);
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
        $user->updateProfile(new Profile(givenName: 'Alice'), Fixtures::now());
        $claims = ClaimsRequest::fromJson('{"id_token":{"email":null,"email_verified":{"essential":true},"family_name":null},"userinfo":{"given_name":null}}');

        return UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            Fixtures::session($user),
            Fixtures::now(),
            ['openid', 'profile', 'email'],
            claims: $claims,
        ));
    }
}
