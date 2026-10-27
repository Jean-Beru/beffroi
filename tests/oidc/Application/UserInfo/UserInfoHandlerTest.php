<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\UserInfo;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Application\Token\PresentedAccessTokenParser;
use Beffroi\Oidc\Tests\Fixture\Bindings;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Application\UserInfo\UserInfoHandler;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Application\Grant\RecordedGrants;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Event\UserInfoAnswered;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\UserInfo\UserInfoErrorResponse;
use Beffroi\Oidc\Exception\InsufficientScopeException;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\TokenBindingNotProvenException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

/**
 * The endpoint end to end below HTTP: tokens minted by the issuers of #8 and signed by the bridge of the
 * core, verified by the same bridge against the published keys, claims read from a real user.
 */
final class UserInfoHandlerTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private Client $client;

    private AuthenticationSession $session;

    private InMemoryAuthenticationSessionRepository $sessions;

    private Jwts $jwts;

    private JwtAccessTokenIssuer $accessTokens;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryDeviceAuthorizationRecordRepository $deviceRecords;

    private InMemoryBackchannelAuthenticationRecordRepository $backchannelRecords;

    private InMemoryAccessTokenRepository $storedTokens;

    private Client $service;

    private UserInfoHandler $handler;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
        $this->user->updateProfile(new Profile('Alice Martin', 'Alice', 'Martin', nickname: 'ali'), Fixtures::now());
        $this->user->changePhoneNumber('+33612345678', false, Fixtures::now());
        $this->client = Clients::public($this->tenant, resources: Clients::resources());
        $this->service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->session = Fixtures::session($this->user);
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->sessions->save($this->session);
        $this->jwts = new Jwts($this->tenant);
        $this->accessTokens = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            Subjects::sealedPerson(),
        );
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->deviceRecords = new InMemoryDeviceAuthorizationRecordRepository();
        $this->backchannelRecords = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->storedTokens = new InMemoryAccessTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $this->handler = $this->handler($users);
    }

    /**
     * Issue #589: the claims of a person served to a client is one of the two reads where a personal datum
     * leaves this provider, so it is an act, naming the client that asked and the person by the subject
     * their account carries.
     */
    #[Test]
    public function servingTheClaimsOfAPersonIsAnAct(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email']);

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        $acts = $this->events->of(UserInfoAnswered::class);
        static::assertCount(1, $acts);
        static::assertSame('spa', $acts[0]->clientId);
        static::assertTrue($acts[0]->subject()->equals($this->user->subject));
    }

    /**
     * Nothing of anybody left, so there is nothing to say a read of: a refusal is not an act of this
     * register (issue #589).
     */
    #[Test]
    public function aRefusedRequestIsNoAct(): void
    {
        // Given
        $refreshed = $this->refreshed(['openid', 'email'], new Scopes([new Scope('email')]));
        $token = Tokens::accessToken($this->accessTokens, $refreshed, Fixtures::now())->value;

        // When
        try {
            $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
        } catch (InsufficientScopeException) {
        }

        // Then
        static::assertSame([], $this->events->of(UserInfoAnswered::class));
    }

    /**
     * OIDC Core §5.3.2: "sub" first, equal to the one of the token; §5.4: the claims of the scopes of the
     * token. RFC 6750 §2.1: the token in the Authorization header, which is how oidc_login sends it.
     */
    #[Test]
    public function itServesTheClaimsOfTheScopesOfTheToken(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email', 'phone']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame('alice-subject', $response->subject);
        static::assertSame($this->jwts->verify($token, 'spa', Fixtures::now())['claims']['sub'], $response->subject);
        static::assertSame(
            [
                'sub' => 'alice-subject',
                'email' => 'alice@acme.example',
                'email_verified' => true,
                'phone_number' => '+33612345678',
                'phone_number_verified' => false,
            ],
            $response->claims,
        );
    }

    /**
     * Architecture §4.6: an opaque token opens the same door, from its record: the scopes, and the claims
     * asked for by name.
     */
    #[Test]
    public function itServesTheClaimsOfAnOpaqueToken(): void
    {
        // Given
        $token = Tokens::accessToken($this->opaque(), $this->authorization(['openid', 'email'], '{"userinfo":{"nickname":null}}'), Fixtures::now())->value;

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame(
            [
                'sub' => 'alice-subject',
                'nickname' => 'ali',
                'email' => 'alice@acme.example',
                'email_verified' => true,
            ],
            $response->claims,
        );
    }

    /**
     * RFC 8705 §3: a token bound to a certificate is honoured when the request presents that very
     * certificate again, whichever shape the token has.
     */
    #[Test]
    #[DataProvider('provideBoundTokens')]
    public function aBoundTokenIsHonouredWhenItsCertificateIsPresentedAgain(string $shape): void
    {
        // Given
        $certificate = Certificates::client();
        $token = $this->boundToken($shape, $certificate);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context(), $certificate);

        // Then
        static::assertSame('alice-subject', $response->subject);
    }

    /**
     * RFC 8705 §3.2: another certificate is another holder, and the resource refuses with invalid_token.
     */
    #[Test]
    #[DataProvider('provideBoundTokens')]
    public function aBoundTokenPresentedWithAnotherCertificateIsRefused(string $shape): void
    {
        // Given
        $token = $this->boundToken($shape, Certificates::client());

        // Then
        $this->expectException(TokenBindingNotProvenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is bound to something this request did not present again (RFC 8705 section 3, RFC 9449 section 7.1).');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context(), Certificates::other());
    }

    /**
     * RFC 8705 §3: a bound token is not a bearer token, and whoever steals it holds bytes that open
     * nothing.
     */
    #[Test]
    #[DataProvider('provideBoundTokens')]
    public function aBoundTokenPresentedWithoutACertificateIsRefused(string $shape): void
    {
        // Given
        $token = $this->boundToken($shape, Certificates::client());

        // Then
        $this->expectException(TokenBindingNotProvenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is bound to something this request did not present again (RFC 8705 section 3, RFC 9449 section 7.1).');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token bound to nothing is a bearer token, honoured by whoever holds it, certificate or not
     * (RFC 6750 §2).
     */
    #[Test]
    public function aBearerTokenIsHonouredByWhoeverHoldsIt(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context(), Certificates::other());

        // Then
        static::assertSame('alice-subject', $response->subject);
    }

    /**
     * The two shapes of access token of architecture §4.6.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideBoundTokens(): iterable
    {
        yield 'an at+jwt carrying its own "cnf"' => ['jwt'];

        yield 'an opaque token whose record carries it' => ['opaque'];
    }

    /**
     * OIDC Core §5.1: "email_verified" a JSON boolean on the wire.
     */
    #[Test]
    public function theVerificationFlagsAreJsonBooleansOnTheWire(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email', 'phone']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame(
            '{"sub":"alice-subject","email":"alice@acme.example","email_verified":true,"phone_number":"+33612345678","phone_number_verified":false}',
            $response->toJson(),
        );
    }

    /**
     * OIDC Core §5.5: the claims asked for by name in "claims.userinfo" are served with or without their
     * scope, read from the token alone (architecture §4.6), and only those: "email" by name is not the
     * "email" scope, so "email_verified" stays out; those of "claims.id_token" went into the ID token and
     * are not served here for that reason. RFC 6750 §2.2: the token in the form body.
     */
    #[Test]
    public function itServesTheClaimsAskedForByNameFromTheTokenAlone(): void
    {
        // Given
        $token = $this->accessToken(['openid'], '{"userinfo":{"nickname":null,"email":{"essential":true},"unknown":null},"id_token":{"name":null}}');

        // When
        $response = $this->handler->handle(
            $this->tenant,
            'GET',
            null,
            [
                'access_token' => $token,
            ],
            Fixtures::context(),
        );

        // Then
        static::assertSame(
            [
                'sub' => 'alice-subject',
                'nickname' => 'ali',
                'email' => 'alice@acme.example',
            ],
            $response->claims,
        );
    }

    /**
     * OIDC Core §5.4: "openid" alone gives "sub" and nothing else; RFC 6749 §6: on a refresh the token
     * carries the narrowed scopes, so UserInfo serves the narrowed claims.
     */
    #[Test]
    public function itServesSubAloneForOpenidAlone(): void
    {
        // Given
        $refreshed = $this->refreshed(['openid', 'email'], new Scopes([Scope::openid()]));
        $token = Tokens::accessToken($this->accessTokens, $refreshed, Fixtures::now())->value;

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame(
            [
                'sub' => 'alice-subject',
            ],
            $response->claims,
        );
    }

    /**
     * RFC 6750 §3.1: no token at all is a 401 with the bare challenge; the handler says so with an
     * exception the integration turns into that response.
     */
    #[Test]
    public function itRefusesARequestWithoutToken(): void
    {
        // When
        try {
            $this->handler->handle($this->tenant, 'GET', null, [], Fixtures::context());
            static::fail('The request should have been refused.');
        } catch (MissingBearerTokenException $exception) {
            // Then
            static::assertSame('Bearer, DPoP', UserInfoErrorResponse::fromException($exception, Bindings::schemes())->challenge());
        }
    }

    /**
     * RFC 6750 §2: both methods at once is invalid_request, before anything is verified.
     */
    #[Test]
    public function itRefusesATokenSentTwice(): void
    {
        // Given
        $token = $this->accessToken(['openid']);

        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->handler->handle(
            $this->tenant,
            'GET',
            'Bearer ' . $token,
            [
                'access_token' => $token,
            ],
            Fixtures::context(),
        );
    }

    /**
     * RFC 6750 §3.1, RFC 9068 §4: an expired token is invalid_token, 401, with a description that tells
     * the client to refresh.
     */
    #[Test]
    public function itRefusesAnExpiredToken(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email']);

        // When
        try {
            $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context(Fixtures::now()->modify('+10 minutes')));
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            // Then
            static::assertSame(
                'Bearer error="invalid_token", error_description="The access token expired."',
                UserInfoErrorResponse::fromException($exception, Bindings::schemes())->challenge(),
            );
        }
    }

    /**
     * RFC 9068 §4: an ID token of this provider presented as an access token (no "typ" at+jwt) is
     * invalid_token, 401.
     */
    #[Test]
    public function itRefusesAnIdTokenPresentedAsAnAccessToken(): void
    {
        // Given
        $authorization = $this->authorization(['openid', 'email']);
        $issuer = new JwtIdTokenIssuer($this->jwts->documents, Subjects::publicKind(), new StandardClaimsProvider(), Algorithms::all());
        $idToken = $issuer->issue(
            $authorization,
            Tokens::accessToken($this->accessTokens, $authorization, Fixtures::now()),
            $issuer->address($authorization->client),
            Fixtures::now(),
        );

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIsOrContains('not an access token');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $idToken, [], Fixtures::context());
    }

    /**
     * RFC 8707 §2: a token asked for a resource is addressed to that resource, and this endpoint is not
     * it. The refusal is the one of RFC 6750 §3.1, whatever else the token is worth.
     */
    #[Test]
    public function itRefusesATokenAddressedToAResource(): void
    {
        // Given
        $code = Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            resources: ResourceIndicators::of([Clients::CALENDAR]),
        );
        $this->grants->save($code);
        $token = Tokens::accessToken($this->accessTokens, UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code), Fixtures::now())->value;

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is addressed to a resource of its own and not to this provider (RFC 8707 section 2).');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * OIDC Core §5.3.1: the access token must come from an OpenID Connect authentication request; one
     * without "openid" is insufficient_scope, 403, and the challenge says which scope.
     */
    #[Test]
    public function itRefusesATokenWithoutOpenidScope(): void
    {
        // Given
        $refreshed = $this->refreshed(['openid', 'email'], new Scopes([new Scope('email')]));
        $token = Tokens::accessToken($this->accessTokens, $refreshed, Fixtures::now())->value;

        // When
        try {
            $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
            static::fail('The token should have been refused.');
        } catch (InsufficientScopeException $exception) {
            // Then
            static::assertSame(403, $exception->statusCode);
            static::assertSame(
                'Bearer error="insufficient_scope", error_description="The access token was not obtained through an OpenID Connect authentication request.", scope="openid"',
                UserInfoErrorResponse::fromException($exception, Bindings::schemes())->challenge(),
            );
        }
    }

    /**
     * RFC 6749 §4.4, RFC 8707 §2: a token a client holds for itself is asked for a resource and addressed
     * to it, and this endpoint is not that resource. It is refused there, before anything of a person is
     * read, so a service acting for itself never reads the claims of anybody.
     */
    #[Test]
    public function itRefusesATokenNobodySignedInFor(): void
    {
        // Given
        $token = Tokens::accessToken(
            $this->accessTokens,
            new ClientAuthorization(
                Grants::clientCredentials(),
                Uuid::v7(),
                $this->service,
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
            ),
            Fixtures::now(),
        )->value;

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is addressed to a resource of its own and not to this provider (RFC 8707 section 2).');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * RFC 6749 §4.1.2: the replay of an authorization code revokes what was issued from it. The access
     * token still verifies on its own (RFC 9068 §4), so a resource server holding only the keys keeps
     * serving it; the provider, which knows where its grants live, refuses it: invalid_token, 401.
     */
    #[Test]
    public function itRefusesATokenOfARevokedGrant(): void
    {
        // Given
        $code = $this->code(['openid', 'email']);
        $token = Tokens::accessToken($this->accessTokens, UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code), Fixtures::now())->value;
        $code->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * RFC 6749 §4.1.2 names every token issued from the code, so an access token obtained by refreshing
     * is refused as well: the family carries the grant of the code it descends from.
     */
    #[Test]
    public function itRefusesARefreshedTokenOfARevokedGrant(): void
    {
        // Given
        $refreshed = $this->refreshed(['openid', 'email'], null);
        $token = Tokens::accessToken($this->accessTokens, $refreshed, Fixtures::now())->value;
        $grant = $this->grants->findByGrantId($refreshed->grantId) ?? static::fail('The refresh carries the grant of the code it descends from.');
        $grant->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token whose grant the provider no longer has is refused the same way: there is nothing left to
     * vouch for it.
     */
    #[Test]
    public function itRefusesATokenWhoseGrantIsGone(): void
    {
        // Given
        $token = Tokens::accessToken(
            $this->accessTokens,
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'never-stored',
                $this->client,
                $this->session,
                Fixtures::now(),
                ['openid'],
            )),
            Fixtures::now(),
        )->value;

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * RFC 8628 §3.4: the tokens of the device grant descend from the device authorization request and from
     * no authorization code, so the record of that request is what says the grant is still alive. Asked of
     * the codes alone, the question had no answer and the token was refused at this endpoint.
     */
    #[Test]
    public function itServesATokenOfTheDeviceGrant(): void
    {
        // Given
        $token = Tokens::accessToken($this->accessTokens, $this->ofADeviceRequest(), Fixtures::now())->value;

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame($this->user->subject->value, $response->claims['sub']);
    }

    /**
     * Architecture §4.3: a device authorization request is revoked as a code is, and the tokens that
     * descend from it stop being served here.
     */
    #[Test]
    public function itRefusesATokenOfARevokedDeviceRequest(): void
    {
        // Given
        $record = Tokens::approvedDeviceRecord($this->client, $this->session, Fixtures::now());
        $this->deviceRecords->save($record);
        $token = Tokens::accessToken($this->accessTokens, $this->ofTheRecord($record->grantId, $record->scopes), Fixtures::now())->value;
        $record->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * CIBA Core §10.1: the tokens of the backchannel grant descend from the backchannel authentication
     * request and from no authorization code, which is the refusal the FAPI-CIBA plan met at this endpoint.
     */
    #[Test]
    public function itServesATokenOfTheBackchannelGrant(): void
    {
        // Given
        $token = Tokens::accessToken($this->accessTokens, $this->ofABackchannelRequest(), Fixtures::now())->value;

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame($this->user->subject->value, $response->claims['sub']);
    }

    /**
     * Architecture §4.3: a backchannel authentication request is revoked as a code is, and the tokens that
     * descend from it stop being served here.
     */
    #[Test]
    public function itRefusesATokenOfARevokedBackchannelRequest(): void
    {
        // Given
        $record = Tokens::approvedBackchannelRecord($this->client, $this->session, Fixtures::now());
        $this->backchannelRecords->save($record);
        $token = Tokens::accessToken($this->accessTokens, $this->ofTheRecord($record->grantId, $record->scopes), Fixtures::now())->value;
        $record->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token that names a user the tenant has disabled opens nothing: invalid_token, the same as a bad
     * one. Nothing about the user is said.
     */
    #[Test]
    public function itRefusesATokenOfADisabledUser(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email']);
        $this->user->disable(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token that names a user the tenant no longer has opens nothing either.
     */
    #[Test]
    public function itRefusesATokenOfAUserGone(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email']);
        $handler = $this->handler(new InMemoryUserRepository());

        // Then
        $this->expectException(InvalidTokenException::class);

        // When
        $handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token of another tenant does not verify against the keys of this one, whatever it says.
     */
    #[Test]
    public function itRefusesATokenOfAnotherTenant(): void
    {
        // Given
        $token = $this->accessToken(['openid']);

        // Then
        $this->expectException(InvalidTokenException::class);

        // When
        $this->handler->handle(Fixtures::tenant('other', 'https://id.other.example'), 'GET', 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * The acceptance of issue #165: a client that registered nothing keeps receiving the JSON answer,
     * which is what every client does today.
     */
    #[Test]
    public function aClientThatRegisteredNothingReceivesTheJson(): void
    {
        // Given
        $token = $this->accessToken(['openid', 'email']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame('application/json', $response->contentType);
        static::assertSame('{"sub":"alice-subject","email":"alice@acme.example","email_verified":true}', $response->body);
    }

    /**
     * OIDC Core §5.3.2: a client that registered a signature receives the same claims as a JWT, served as
     * "application/jwt", and the JWT names who wrote it and for whom, which the JSON has no room to say.
     */
    #[Test]
    public function aClientThatRegisteredASignatureReceivesAJwt(): void
    {
        // Given
        $this->client = Clients::encryptedFor($this->tenant, userInfo: ResponseFormat::signed(), clientId: 'spa');
        $token = $this->reopenedWith(['openid', 'email']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame('application/jwt', $response->contentType);
        ['claims' => $claims] = $this->jwts->verify($response->body, 'spa', Fixtures::now(), ['iss', 'aud']);
        static::assertSame(
            [
                'sub' => 'alice-subject',
                'email' => 'alice@acme.example',
                'email_verified' => true,
                'iss' => (string) $this->tenant->issuer,
                'aud' => 'spa',
            ],
            $claims,
        );
    }

    /**
     * §5.3.2: a client that registered an encryption receives a JWE it opens with its own key, carrying
     * the signed answer.
     */
    #[Test]
    public function aClientThatRegisteredAnEncryptionReceivesAJweItOpens(): void
    {
        // Given
        $this->client = Clients::encryptedFor($this->tenant, userInfo: ResponseFormat::signed(null, ClientEncryption::registration()), clientId: 'spa');
        $token = $this->reopenedWith(['openid', 'email']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame('application/jwt', $response->contentType);
        ['header' => $header, 'payload' => $signed] = ClientEncryption::open($response->body);
        static::assertSame('JWT', $header['cty']);
        static::assertSame('alice-subject', $this->jwts->verify($signed, 'spa', Fixtures::now(), ['iss', 'aud'])['claims']['sub']);
    }

    /**
     * §5.3.2: an answer may be encrypted without being signed, and what the JWE carries is then the JSON
     * of the claims, which says nothing about who wrote it beyond the key it was addressed to.
     */
    #[Test]
    public function aClientThatRegisteredOnlyAnEncryptionReceivesTheJsonInsideTheJwe(): void
    {
        // Given
        $this->client = Clients::encryptedFor($this->tenant, userInfo: ResponseFormat::unsigned(ClientEncryption::registration()), clientId: 'spa');
        $token = $this->reopenedWith(['openid', 'email']);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());

        // Then
        ['header' => $header, 'payload' => $payload] = ClientEncryption::open($response->body);
        static::assertArrayNotHasKey('cty', $header);
        static::assertSame(
            '{"sub":"alice-subject","email":"alice@acme.example","email_verified":true,"iss":"' . $this->tenant->issuer . '","aud":"spa"}',
            $payload,
        );
    }

    /**
     * A token issued to the client as it is now, once the registration under test replaced it.
     *
     * @param list<string> $scopes
     */
    private function reopenedWith(array $scopes): string
    {
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $this->handler = $this->handler($users);

        return $this->accessToken($scopes);
    }

    private function handler(InMemoryUserRepository $users): UserInfoHandler
    {
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $clients->save($this->service);

        return new UserInfoHandler(
            new AccessTokenInspector(
                AccessTokenShapes::verifier(
                    new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                    $clients,
                    $this->storedTokens,
                    Subjects::publicKind(),
                ),
                $this->sessions,
                new RecordedGrants([$this->grants, $this->deviceRecords, $this->backchannelRecords]),
                Subjects::personOfAToken($users),
            ),
            $this->jwts->documents,
            Proofs::verifier(),
            new Endpoints(),
            Subjects::publicKind(),
            new StandardClaimsProvider(),
            new PresentedAccessTokenParser(Bindings::wired()),
            $this->events,
        );
    }

    /**
     * RFC 9449 §7.1: a token bound to a key is honoured when the request carries a proof of that key,
     * made for this request and naming this very token, whichever shape the token has.
     */
    #[Test]
    #[DataProvider('provideBoundTokens')]
    public function aKeyBoundTokenIsHonouredWhenTheKeyIsProvedAgain(string $shape): void
    {
        // Given
        $token = $this->keyBoundToken($shape);

        // When
        $response = $this->handler->handle($this->tenant, 'GET', 'DPoP ' . $token, [], Fixtures::context(), null, $this->proof($token));

        // Then
        static::assertSame('alice-subject', $response->subject);
    }

    /**
     * A token issued against one key and presented with a proof of another opens nothing.
     */
    #[Test]
    #[DataProvider('provideBoundTokens')]
    public function aKeyBoundTokenPresentedWithAnotherKeyIsRefused(string $shape): void
    {
        // Given
        $token = $this->keyBoundToken($shape);

        // Then
        $this->expectException(TokenBindingNotProvenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is bound to something this request did not present again (RFC 8705 section 3, RFC 9449 section 7.1).');

        // When
        $this->handler->handle($this->tenant, 'GET', 'DPoP ' . $token, [], Fixtures::context(), null, $this->proof($token, Proofs::otherKey()));
    }

    /**
     * RFC 9449 §7.1: a token bound to a key is presented under the DPoP scheme, and refused when it is
     * presented as a bearer token, with the challenge naming the scheme that would have worked.
     */
    #[Test]
    #[DataProvider('provideBoundTokens')]
    public function aKeyBoundTokenPresentedAsABearerTokenIsRefused(string $shape): void
    {
        // Given
        $token = $this->keyBoundToken($shape);

        // When
        try {
            $this->handler->handle($this->tenant, 'GET', 'Bearer ' . $token, [], Fixtures::context());
            static::fail('A token bound to a key is not a bearer token.');
        } catch (TokenBindingNotProvenException $exception) {
            // Then
            static::assertSame(
                'invalid_token: The access token is bound to a key and was presented as a bearer token (RFC 9449 section 7.1).',
                $exception->getMessage(),
            );
            static::assertSame('DPoP', $exception->challengeScheme());
            static::assertSame(
                'DPoP error="invalid_token", error_description="The access token is bound to a key and was presented as a bearer token (RFC 9449 section 7.1)."',
                UserInfoErrorResponse::fromException($exception, Bindings::schemes())->challenge(),
            );
        }
    }

    /**
     * RFC 9449 §7.1: the proof names the token it accompanies, so that one taken from another request
     * of the same client does not open this one.
     */
    #[Test]
    public function aProofMadeForAnotherTokenIsRefused(): void
    {
        // Given
        $token = $this->keyBoundToken('jwt');

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIs('invalid_dpop_proof: The ath of the DPoP proof is not the access token this request presents (RFC 9449 section 7.1).');

        // When
        $this->handler->handle($this->tenant, 'GET', 'DPoP ' . $token, [], Fixtures::context(), null, $this->proof('another-access-token'));
    }

    /**
     * A token of the shape named, bound to the key of the proofs fixture (RFC 9449 §6.1).
     */
    private function keyBoundToken(string $shape): string
    {
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            $this->code(['openid', 'email']),
            Proofs::thumbprintOf(Proofs::key()),
        );
        if ($shape === 'jwt') {
            return Tokens::accessToken($this->accessTokens, $authorization, Fixtures::now())->value;
        }

        return Tokens::accessToken($this->opaque(), $authorization, Fixtures::now())->value;
    }

    /**
     * A proof for a GET of the UserInfo endpoint of the tenant, naming the token it accompanies.
     */
    private function proof(string $accessToken, ?JWK $key = null): string
    {
        return Proofs::proof('GET', Endpoints::of($this->tenant)->userinfo, Fixtures::now(), $accessToken, [], [], $key);
    }

    /**
     * A token of the shape named, bound to the certificate given (RFC 8705 §3).
     */
    private function boundToken(string $shape, ClientCertificate $certificate): string
    {
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            $this->code(['openid', 'email']),
            CertificateConfirmation::ofCertificate($certificate),
        );
        if ($shape === 'jwt') {
            return Tokens::accessToken($this->accessTokens, $authorization, Fixtures::now())->value;
        }

        return Tokens::accessToken($this->opaque(), $authorization, Fixtures::now())->value;
    }

    private function opaque(): OpaqueAccessTokenIssuer
    {
        return new OpaqueAccessTokenIssuer($this->storedTokens, Secrets::drawer());
    }

    /**
     * @param list<string> $scopes
     */
    private function accessToken(array $scopes, ?string $claims = null): string
    {
        return Tokens::accessToken($this->accessTokens, $this->authorization($scopes, $claims), Fixtures::now())->value;
    }

    /**
     * The authorization the device grant builds, its grant named by the record it spent (RFC 8628 §3.4).
     */
    private function ofADeviceRequest(): UserAuthorization
    {
        $record = Tokens::approvedDeviceRecord($this->client, $this->session, Fixtures::now(), ['openid', 'email']);
        $this->deviceRecords->save($record);

        return $this->ofTheRecord($record->grantId, $record->scopes);
    }

    /**
     * The authorization the backchannel grant builds, its grant named by the record it spent (CIBA Core
     * §10.1).
     */
    private function ofABackchannelRequest(): UserAuthorization
    {
        $record = Tokens::approvedBackchannelRecord($this->client, $this->session, Fixtures::now(), ['openid', 'email']);
        $this->backchannelRecords->save($record);

        return $this->ofTheRecord($record->grantId, $record->scopes);
    }

    private function ofTheRecord(Uuid $grantId, Scopes $scopes): UserAuthorization
    {
        return new UserAuthorization(
            Grants::deviceCode(),
            $grantId,
            $this->client,
            $this->session,
            $scopes,
            $scopes,
            null,
            null,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
        );
    }

    /**
     * @param list<string> $scopes
     */
    private function authorization(array $scopes, ?string $claims = null): UserAuthorization
    {
        return UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $this->code($scopes, $claims));
    }

    /**
     * A code of the grant the tokens descend from, in the repository the endpoint reads to learn whether
     * that grant is still alive.
     *
     * @param list<string> $scopes
     */
    private function code(array $scopes, ?string $claims = null): AuthorizationCode
    {
        $code = Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            $scopes,
            claims: $claims === null ? null : ClaimsRequest::fromJson($claims),
        );
        $this->grants->save($code);

        return $code;
    }

    /**
     * The authorization of a refresh, whose tokens descend from the same grant as the code.
     *
     * @param list<string> $granted
     */
    private function refreshed(array $granted, ?Scopes $scopes): UserAuthorization
    {
        $family = Tokens::family(Fixtures::now(), $this->client->tenant, grantId: $this->code($granted)->grantId);

        return UserAuthorization::fromRefreshToken(
            Grants::refreshToken(),
            Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), $family, $granted),
            $scopes,
        );
    }
}
