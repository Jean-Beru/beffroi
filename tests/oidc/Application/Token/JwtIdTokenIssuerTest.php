<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Tests\Fixture\Grants;
use function array_keys;
use function base64_encode;
use DateInterval;
use function explode;
use function hash;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FixedPairwiseSalt;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\PairwiseSaltBehindAnOutage;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function strtr;
use function substr;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Beffroi\Oidc\Tests\Fixture\Shapes;

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
     * OIDC Core §2
     */
    #[Test]
    public function theHeaderNamesTheActiveKeyAndNoType(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());

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
     * OIDC Core §2, Architecture §4.6
     */
    #[Test]
    public function thePayloadCarriesTheClaimsOfOidcCoreInOrder(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());

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
     * Architecture §4.5
     */
    #[Test]
    public function aKmsThatDoesNotAnswerForThePairwiseSaltIsToldWhenTheTokenIsAddressed(): void
    {
        // Given
        $salts = new PairwiseSaltBehindAnOutage();
        $salts->down = true;
        $issuer = new JwtIdTokenIssuer($this->jwts->documents, Subjects::bothKinds(salts: $salts), new StandardClaimsProvider(), Algorithms::all());

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs(PairwiseSaltBehindAnOutage::WORDS_OF_THE_KMS);

        // When
        $issuer->address(Clients::pairwise($this->session->tenant));
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function anIdTokenOfAPairwiseClientNamesWhoeverSignedInByWhatWasOpenedWhenItWasAddressed(): void
    {
        // Given
        $salts = new PairwiseSaltBehindAnOutage();
        $issuer = new JwtIdTokenIssuer($this->jwts->documents, Subjects::bothKinds(salts: $salts), new StandardClaimsProvider(), Algorithms::all());
        $client = Clients::pairwise($this->session->tenant);
        $addressed = $issuer->address($client);
        $salts->down = true;
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            ['openid', 'profile'],
        ));

        // When
        $idToken = $issuer->issue($authorization, $this->accessToken, $addressed, Fixtures::now());

        // Then
        ['claims' => $claims] = $this->jwts->verify($idToken, 'pairwise-app', Fixtures::now()->modify('+9 minutes'));
        static::assertSame(
            Subjects::pairwiseKind(new FixedPairwiseSalt())->resolve($this->session->user, $client)->value,
            $claims['sub'] ?? null,
        );
    }

    /**
     * Front-Channel Logout 1.0 §3, Back-Channel Logout 1.0 §2.1
     *
     * @param callable(self): Client $client
     */
    #[Test]
    #[DataProvider('provideClientsOfEveryLogoutRegistration')]
    public function theSessionIsNamedInTheIdTokenOfEveryClient(callable $client): void
    {
        // Given
        $this->client = $client($this);
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());

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
     * OIDC Core §3.1.3.6, appendix A.3
     */
    #[Test]
    public function theAtHashIsTheLeftHalfOfTheSha256OfTheAccessToken(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());

        // When
        $claims = $this->jwts->verify($idToken, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(rtrim(strtr(base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 0, 16)), '+/', '-_'), '='), $claims['at_hash']);
        static::assertSame('77QmUPtjPfzWtF2AnpK9RQ', $claims['at_hash']);
    }

    /**
     * OIDC Core §12.2
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
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $this->issuer->address($authorization->client), $later);

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
     * OIDC Core §5.5, §5.4
     */
    #[Test]
    public function itAddsTheClaimsRequestedForTheIdTokenAndNoOther(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationWithRequestedClaims(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());

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
     * OIDC Core §5.1
     */
    #[Test]
    public function theVerificationFlagIsAJsonBooleanOnTheWire(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationWithRequestedClaims(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());

        // When
        $decoded = $this->jwts->verify($idToken, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertTrue($decoded['email_verified']);
        static::assertStringContainsString('"email_verified":true', Jwts::rawPayload($idToken));
    }

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

            public function claimsOf(Scopes $scopes): array
            {
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
            $issuer->address($this->client),
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

            public function claimsOf(Scopes $scopes): array
            {
                return [];
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
        $claims = $this->jwts->verify(
            $issuer->issue($authorization, $this->accessToken, $issuer->address($authorization->client), Fixtures::now()),
            'spa',
            Fixtures::now(),
        )['claims'];

        // Then
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame('Alice', $claims['name']);
    }

    /**
     * Architecture §4.6
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
        $idToken = $issuer->issue($this->authorizationFromCode(), $this->accessToken, $issuer->address($this->client), Fixtures::now());

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
        $idToken = $issuer->issue($this->authorizationFromCode(), $this->accessToken, $issuer->address($this->client), Fixtures::now());

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+61 minutes'));
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function theTokenServesAsAnIdTokenHint(): void
    {
        // Given
        $idToken = $this->issuer->issue($this->authorizationFromCode(), $this->accessToken, $this->issuer->address($this->client), Fixtures::now());
        $verifier = new IdTokenHintVerifier(new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()));

        // When
        $subject = $verifier->verify($this->client, $idToken);

        // Then
        static::assertSame('alice-subject', $subject->value);
    }

    /**
     * OIDC Core §3.1.3.7 step 3
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
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $this->issuer->address($authorization->client), Fixtures::now());

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($idToken, 'other', Fixtures::now());
    }

    /**
     * OIDC Registration §2
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
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $this->issuer->address($authorization->client), Fixtures::now());

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
     * OIDC Core §3.1.3.6
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
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $this->issuer->address($authorization->client), Fixtures::now());

        // Then
        ['claims' => $claims] = $this->jwts->verify($idToken, 'spa', Fixtures::now()->modify('+9 minutes'));
        static::assertSame(self::leftHalf(hash('sha512', self::ACCESS_TOKEN, true)), $claims['at_hash']);
    }

    private static function leftHalf(string $digest): string
    {
        return rtrim(strtr(base64_encode(substr($digest, 0, 32)), '+/', '-_'), '=');
    }

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
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $this->issuer->address($authorization->client), Fixtures::now());

        // Then
        ['header' => $header, 'payload' => $signed] = ClientEncryption::open($idToken);
        static::assertSame('ECDH-ES+A256KW', $header['alg']);
        static::assertSame('A256GCM', $header['enc']);
        static::assertSame(ClientEncryption::KEY_ID, $header['kid']);
        // RFC 7519 §5.2: the payload of the JWE is itself a JWT.
        static::assertSame('JWT', $header['cty']);
        ['claims' => $claims] = $this->jwts->verify($signed, 'encrypted-client', Fixtures::now()->modify('+9 minutes'));
        static::assertSame('alice-subject', $claims['sub']);
    }

    /**
     * OIDC Core §16.14
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
        $idToken = $this->issuer->issue($authorization, $this->accessToken, $this->issuer->address($authorization->client), Fixtures::now());

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
