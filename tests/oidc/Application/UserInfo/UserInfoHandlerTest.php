<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\UserInfo;

use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsVerifier;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Application\Token\JwtIdTokenIssuer;
use Heidi\Oidc\Application\UserInfo\UserInfoHandler;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\UserInfo\UserInfoErrorResponse;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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

    private Jwts $jwts;

    private JwtAccessTokenIssuer $accessTokens;

    private InMemoryAuthorizationCodeRepository $grants;

    private UserInfoHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
        $this->user->updateProfile(new Profile('Alice Martin', 'Alice', 'Martin', nickname: 'ali'), Fixtures::now());
        $this->user->changePhoneNumber('+33612345678', false, Fixtures::now());
        $this->client = Clients::public($this->tenant);
        $this->session = Fixtures::session($this->user);
        $this->jwts = new Jwts($this->tenant);
        $this->accessTokens = new JwtAccessTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver());
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $this->handler = $this->handler($users);
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
        $response = $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame('alice-subject', $response->subject);
        static::assertSame($this->jwts->verify($token, 'spa', Fixtures::now())['claims']['sub'], $response->subject);
        static::assertSame([
            'sub' => 'alice-subject',
            'email' => 'alice@acme.example',
            'email_verified' => true,
            'phone_number' => '+33612345678',
            'phone_number_verified' => false,
        ], $response->claims);
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
        $response = $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame('{"sub":"alice-subject","email":"alice@acme.example","email_verified":true,"phone_number":"+33612345678","phone_number_verified":false}', $response->toJson());
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
        $response = $this->handler->handle($this->tenant, null, [
            'access_token' => $token,
        ], Fixtures::context());

        // Then
        static::assertSame([
            'sub' => 'alice-subject',
            'nickname' => 'ali',
            'email' => 'alice@acme.example',
        ], $response->claims);
    }

    /**
     * OIDC Core §5.4: "openid" alone gives "sub" and nothing else; RFC 6749 §6: on a refresh the token
     * carries the narrowed scopes, so UserInfo serves the narrowed claims.
     */
    #[Test]
    public function itServesSubAloneForOpenidAlone(): void
    {
        // Given
        $refreshed = $this->refreshed(['openid', 'email'], [Scope::openid()]);
        $token = $this->accessTokens->issue($refreshed, Fixtures::now())->value;

        // When
        $response = $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());

        // Then
        static::assertSame([
            'sub' => 'alice-subject',
        ], $response->claims);
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
            $this->handler->handle($this->tenant, null, [], Fixtures::context());
            static::fail('The request should have been refused.');
        } catch (MissingBearerTokenException $exception) {
            // Then
            static::assertSame('Bearer', UserInfoErrorResponse::fromException($exception)->challenge());
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
        $this->handler->handle($this->tenant, 'Bearer ' . $token, [
            'access_token' => $token,
        ], Fixtures::context());
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
            $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context(Fixtures::now()->modify('+10 minutes')));
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            // Then
            static::assertSame('Bearer error="invalid_token", error_description="The access token expired."', UserInfoErrorResponse::fromException($exception)->challenge());
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
        $idToken = new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider())
            ->issue($authorization, $this->accessTokens->issue($authorization, Fixtures::now()), Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIsOrContains('not an access token');

        // When
        $this->handler->handle($this->tenant, 'Bearer ' . $idToken, [], Fixtures::context());
    }

    /**
     * OIDC Core §5.3.1: the access token must come from an OpenID Connect authentication request; one
     * without "openid" is insufficient_scope, 403, and the challenge says which scope.
     */
    #[Test]
    public function itRefusesATokenWithoutOpenidScope(): void
    {
        // Given
        $refreshed = $this->refreshed(['openid', 'email'], [new Scope('email')]);
        $token = $this->accessTokens->issue($refreshed, Fixtures::now())->value;

        // When
        try {
            $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
            static::fail('The token should have been refused.');
        } catch (InsufficientScopeException $exception) {
            // Then
            static::assertSame(403, $exception->statusCode);
            static::assertSame('Bearer error="insufficient_scope", error_description="The access token was not obtained through an OpenID Connect authentication request.", scope="openid"', UserInfoErrorResponse::fromException($exception)->challenge());
        }
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
        $token = $this->accessTokens->issue(GrantedAuthorization::fromAuthorizationCode($code), Fixtures::now())->value;
        $code->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
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
        $token = $this->accessTokens->issue($refreshed, Fixtures::now())->value;
        $grant = $this->grants->findByGrantId($refreshed->grantId);
        static::assertNotNull($grant, 'the refresh carries the grant of the code it descends from');
        $grant->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token whose grant the provider no longer has is refused the same way: there is nothing left to
     * vouch for it.
     */
    #[Test]
    public function itRefusesATokenWhoseGrantIsGone(): void
    {
        // Given
        $token = $this->accessTokens->issue(GrantedAuthorization::fromAuthorizationCode(Tokens::code('never-stored', $this->client, $this->session, Fixtures::now(), ['openid'])), Fixtures::now())->value;

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
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
        $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
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
        $handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
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
        $this->handler->handle(Fixtures::tenant('other', 'https://id.other.example'), 'Bearer ' . $token, [], Fixtures::context());
    }

    private function handler(InMemoryUserRepository $users): UserInfoHandler
    {
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);

        return new UserInfoHandler(
            new AccessTokenVerifier(new JwtFrameworkJwsVerifier($this->jwts->keys), $clients),
            $this->grants,
            $users,
            new PublicSubjectIdentifierResolver(),
            new StandardClaimsProvider(),
        );
    }

    /**
     * @param list<string> $scopes
     */
    private function accessToken(array $scopes, ?string $claims = null): string
    {
        return $this->accessTokens->issue($this->authorization($scopes, $claims), Fixtures::now())->value;
    }

    /**
     * @param list<string> $scopes
     */
    private function authorization(array $scopes, ?string $claims = null): GrantedAuthorization
    {
        return GrantedAuthorization::fromAuthorizationCode($this->code($scopes, $claims));
    }

    /**
     * A code of the grant the tokens descend from, in the repository the endpoint reads to learn whether
     * that grant is still alive.
     *
     * @param list<string> $scopes
     */
    private function code(array $scopes, ?string $claims = null): AuthorizationCode
    {
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), $scopes, claims: $claims === null ? null : ClaimsRequest::fromJson($claims));
        $this->grants->save($code);

        return $code;
    }

    /**
     * The authorization of a refresh, whose tokens descend from the same grant as the code.
     *
     * @param list<string> $granted
     * @param list<Scope>|null $scopes
     */
    private function refreshed(array $granted, ?array $scopes): GrantedAuthorization
    {
        $family = Tokens::family(Fixtures::now(), grantId: $this->code($granted)->grantId);

        return GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), $family, $granted), $scopes);
    }
}
