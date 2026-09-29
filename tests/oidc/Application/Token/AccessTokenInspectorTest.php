<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Tests\Fixture\AccessTokenShapes;
use Heidi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\ClientAuthorization;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Heidi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

/**
 * The checks the provider's own resources add to the verification (architecture §4.6): the session, the
 * grant and the user, asked in one way of both shapes of token, an opaque one being the shape used
 * wherever the shape is not what the test is about.
 */
final class AccessTokenInspectorTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private Client $client;

    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryAccessTokenRepository $tokens;

    private InMemoryAuthenticationSessionRepository $sessions;

    private Jwts $jwts;

    private InMemoryClientRepository $clients;

    private AccessTokenInspector $inspector;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->client = Clients::public($this->tenant);
        $this->session = Fixtures::session($this->user);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->sessions->save($this->session);
        $this->jwts = new Jwts($this->tenant);
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $this->clients = new InMemoryClientRepository();
        $this->clients->save($this->client);
        $this->inspector = new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                $this->clients,
                $this->tokens,
                Subjects::publicKind(),
            ),
            $this->sessions,
            $this->grants,
            Subjects::ofAProvider($users),
        );
    }

    #[Test]
    public function itHandsOverTheVerifiedTokenAndItsUser(): void
    {
        // Given
        $token = $this->tokenOf($this->code());

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame($this->user, $inspected->user);
        static::assertSame($this->client, $inspected->token->client);
        static::assertSame('alice-subject', (string) $inspected->token->subject);
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself descends from no session and names nobody, so
     * neither question is asked of it; it is honoured on what it carries, and the resource that answers
     * for a user is told there is none.
     */
    #[Test]
    public function itHandsOverATokenNobodySignedInForWithoutAUser(): void
    {
        // Given
        $token = $this->clientToken();

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertNull($inspected->user);
        static::assertNull($inspected->token->signIn);
        static::assertSame('batch', (string) $inspected->token->subject);
    }

    /**
     * The session of the tokens of a user having ended says nothing about a token nobody signed in for: it
     * has no session to have ended and no grant of a browser flow to be revoked with one.
     */
    #[Test]
    public function aTokenNobodySignedInForOutlivesTheLogoutOfEverybody(): void
    {
        // Given
        $token = $this->clientToken();
        $this->session->end(SessionEnd::User, Fixtures::now()->modify('+1 minute'));

        // When
        $inspected = $this->inspector->inspect($this->tenant, $token, Fixtures::now());

        // Then
        static::assertNull($inspected->user);
    }

    /**
     * RFC 6749 §4.1.2: the replay of the code revoked the grant; every token descending from it is refused.
     */
    #[Test]
    public function itRefusesATokenOfARevokedGrant(): void
    {
        // Given
        $code = $this->code();
        $token = $this->tokenOf($code);
        $code->revoke(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * A grant the provider no longer keeps is a grant it cannot vouch for.
     */
    #[Test]
    public function itRefusesATokenWhoseGrantIsGone(): void
    {
        // Given
        $token = $this->tokenOf(Tokens::code('the-code', $this->client, $this->session, Fixtures::now()));

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a grant this provider revoked.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    #[Test]
    public function itRefusesATokenOfADisabledUser(): void
    {
        // Given
        $token = $this->tokenOf($this->code());
        $this->user->disable(Fixtures::now());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    #[Test]
    public function itRefusesATokenOfAUserGone(): void
    {
        // Given
        $inspector = new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                new InMemoryClientRepository(),
                $this->tokens,
                Subjects::publicKind(),
            ),
            $this->sessions,
            $this->grants,
            Subjects::ofAProvider(new InMemoryUserRepository()),
        );
        $token = $this->tokenOf($this->code());

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token names a user this provider no longer serves.');

        // When
        $inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * What the verifier refuses, the inspector refuses, before any grant or user is looked at.
     */
    #[Test]
    public function itRefusesWhatTheVerifierRefuses(): void
    {
        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is not an access token issued by this provider.');

        // When
        $this->inspector->inspect($this->tenant, 'unknown', Fixtures::now());
    }

    /**
     * Architecture §4.9 and issue #150: what a logout ends, it ends for both shapes of token. An opaque
     * one is refused by the record the provider keeps, an "at+jwt" by the "sid" it carries, and the
     * question is asked in the same place for both.
     */
    #[Test]
    #[DataProvider('provideAccessTokenShapes')]
    public function itRefusesATokenOfASessionThatEnded(string $shape): void
    {
        // Given
        $token = $this->tokenOfShape($shape, $this->code());
        $this->session->end(SessionEnd::User, Fixtures::now()->modify('+1 minute'));

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a session this provider ended.');

        // When
        $this->inspector->inspect($this->tenant, $token, Fixtures::now()->modify('+2 minutes'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAccessTokenShapes(): iterable
    {
        yield 'opaque' => ['opaque'];
        yield 'at+jwt' => ['jwt'];
    }

    /**
     * A session the provider no longer keeps is a session it cannot vouch for, as a grant it no longer
     * keeps is.
     */
    #[Test]
    public function itRefusesATokenWhoseSessionIsGone(): void
    {
        // Given
        $token = $this->tokenOfShape('jwt', $this->code());
        $sessions = new InMemoryAuthenticationSessionRepository();
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $inspector = new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($this->jwts->keys, Algorithms::all()),
                $clients,
                $this->tokens,
                Subjects::publicKind(),
            ),
            $sessions,
            $this->grants,
            Subjects::ofAProvider($users),
        );

        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token descends from a session this provider ended.');

        // When
        $inspector->inspect($this->tenant, $token, Fixtures::now());
    }

    /**
     * An opaque token a client holds for itself (RFC 6749 §4.4), of a service client the repository knows.
     */
    private function clientToken(): string
    {
        $service = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clients->save($service);

        return $this->opaque()->issue(
            new ClientAuthorization(
                Grants::clientCredentials(),
                Uuid::v7(),
                $service,
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
            ),
            Fixtures::now(),
        )->value;
    }

    private function code(): AuthorizationCode
    {
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now());
        $this->grants->save($code);

        return $code;
    }

    private function tokenOf(AuthorizationCode $code): string
    {
        return $this->opaque()->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            Fixtures::now(),
        )->value;
    }

    private function opaque(): OpaqueAccessTokenIssuer
    {
        return new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer());
    }

    /**
     * The same grant in either shape: the record the repository keeps, or the "at+jwt" the issuer mints
     * and the bridge of the core verifies.
     */
    private function tokenOfShape(string $shape, AuthorizationCode $code): string
    {
        if ($shape === 'opaque') {
            return $this->tokenOf($code);
        }

        return new JwtAccessTokenIssuer($this->jwts->signer, Subjects::publicKind(), Algorithms::all(), new SymfonyUuidGenerator())->issue(
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code),
            Fixtures::now(),
        )->value;
    }
}
