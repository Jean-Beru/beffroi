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
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
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
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $this->handler = $this->handler($users);
    }

    /**
     * OIDC Core §5.3.2: "sub" first, equal to the one of the token; §5.4: the claims of the scopes of the
     * token; §5.1: "email_verified" a JSON boolean on the wire. RFC 6750 §2.1: the token in the
     * Authorization header, which is how oidc_login sends it.
     */
    #[Test]
    public function itServesTheClaimsOfTheScopesOfTheToken(): void
    {
        $token = $this->accessToken(['openid', 'email', 'phone']);

        $response = $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());

        static::assertSame('alice-subject', $response->subject);
        static::assertSame($this->jwts->verify($token, 'spa', Fixtures::now())['claims']['sub'], $response->subject);
        static::assertSame([
            'sub' => 'alice-subject',
            'email' => 'alice@acme.example',
            'email_verified' => true,
            'phone_number' => '+33612345678',
            'phone_number_verified' => false,
        ], $response->claims);
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
        $token = $this->accessToken(['openid'], '{"userinfo":{"nickname":null,"email":{"essential":true},"unknown":null},"id_token":{"name":null}}');

        $response = $this->handler->handle($this->tenant, null, [
            'access_token' => $token,
        ], Fixtures::context());

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
        $refreshed = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'email']), [Scope::openid()]);

        $response = $this->handler->handle($this->tenant, 'Bearer ' . $this->accessTokens->issue($refreshed, Fixtures::now())->value, [], Fixtures::context());

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
        try {
            $this->handler->handle($this->tenant, null, [], Fixtures::context());
            static::fail('The request should have been refused.');
        } catch (MissingBearerTokenException $exception) {
            static::assertSame('Bearer', UserInfoErrorResponse::fromException($exception)->challenge());
        }
    }

    /**
     * RFC 6750 §2: both methods at once is invalid_request, before anything is verified.
     */
    #[Test]
    public function itRefusesATokenSentTwice(): void
    {
        $token = $this->accessToken(['openid']);

        $this->expectException(InvalidRequestException::class);
        $this->handler->handle($this->tenant, 'Bearer ' . $token, [
            'access_token' => $token,
        ], Fixtures::context());
    }

    /**
     * RFC 6750 §3.1, RFC 9068 §4: an expired token, or an ID token of this provider presented as an
     * access token (no "typ" at+jwt), is invalid_token, 401.
     */
    #[Test]
    public function itRefusesAnExpiredTokenAndAnIdToken(): void
    {
        $authorization = $this->authorization(['openid', 'email']);
        $accessToken = $this->accessTokens->issue($authorization, Fixtures::now());
        $idToken = new JwtIdTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver(), new StandardClaimsProvider())
            ->issue($authorization, $accessToken, Fixtures::now());

        try {
            $this->handler->handle($this->tenant, 'Bearer ' . $accessToken->value, [], Fixtures::context(Fixtures::now()->modify('+10 minutes')));
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            static::assertSame('Bearer error="invalid_token", error_description="The access token expired."', UserInfoErrorResponse::fromException($exception)->challenge());
        }
        try {
            $this->handler->handle($this->tenant, 'Bearer ' . $idToken, [], Fixtures::context());
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            static::assertSame(401, $exception->statusCode);
            static::assertStringContainsString('not an access token', $exception->errorDescription);
        }
    }

    /**
     * OIDC Core §5.3.1: the access token must come from an OpenID Connect authentication request; one
     * without "openid" is insufficient_scope, 403, and the challenge says which scope.
     */
    #[Test]
    public function itRefusesATokenWithoutOpenidScope(): void
    {
        $refreshed = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'email']), [new Scope('email')]);
        $token = $this->accessTokens->issue($refreshed, Fixtures::now())->value;

        try {
            $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
            static::fail('The token should have been refused.');
        } catch (InsufficientScopeException $exception) {
            static::assertSame(403, $exception->statusCode);
            static::assertSame('Bearer error="insufficient_scope", error_description="The access token was not obtained through an OpenID Connect authentication request.", scope="openid"', UserInfoErrorResponse::fromException($exception)->challenge());
        }
    }

    /**
     * A token that names a user the tenant no longer has, or has disabled, opens nothing: invalid_token,
     * the same as a bad one. Nothing about the user is said.
     */
    #[Test]
    public function itRefusesATokenOfAUserGoneOrDisabled(): void
    {
        $token = $this->accessToken(['openid', 'email']);
        $this->user->disable(Fixtures::now());
        try {
            $this->handler->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
            static::fail('The token should have been refused.');
        } catch (InvalidTokenException $exception) {
            static::assertSame(401, $exception->statusCode);
            static::assertSame('The access token names a user this provider no longer serves.', $exception->errorDescription);
        }

        $this->expectException(InvalidTokenException::class);
        $this->handler(new InMemoryUserRepository())
            ->handle($this->tenant, 'Bearer ' . $token, [], Fixtures::context());
    }

    /**
     * A token of another tenant does not verify against the keys of this one, whatever it says.
     */
    #[Test]
    public function itRefusesATokenOfAnotherTenant(): void
    {
        $token = $this->accessToken(['openid']);

        $this->expectException(InvalidTokenException::class);
        $this->handler->handle(Fixtures::tenant('other', 'https://id.other.example'), 'Bearer ' . $token, [], Fixtures::context());
    }

    private function handler(InMemoryUserRepository $users): UserInfoHandler
    {
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);

        return new UserInfoHandler(
            new AccessTokenVerifier(new JwtFrameworkJwsVerifier($this->jwts->keys), $clients),
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
        return GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), $scopes, claims: $claims === null ? null : ClaimsRequest::fromJson($claims)));
    }
}
