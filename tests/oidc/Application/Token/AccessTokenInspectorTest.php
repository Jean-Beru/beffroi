<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The checks the provider's own resources add to the verification (architecture §4.6): an opaque token
 * is the shape used, the JWT one goes through the same verifier and the same inspector.
 */
final class AccessTokenInspectorTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private Client $client;

    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryAccessTokenRepository $tokens;

    private AccessTokenInspector $inspector;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->client = Clients::public($this->tenant);
        $this->session = Fixtures::session($this->user);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $users = new InMemoryUserRepository();
        $users->save($this->user);
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $this->inspector = new AccessTokenInspector(new AccessTokenVerifier(new FakeJwsVerifier(), $clients, $this->tokens, new PublicSubjectIdentifierResolver()), $this->grants, $users);
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
        $inspector = new AccessTokenInspector(new AccessTokenVerifier(new FakeJwsVerifier(), new InMemoryClientRepository(), $this->tokens, new PublicSubjectIdentifierResolver()), $this->grants, new InMemoryUserRepository());
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

    private function code(): AuthorizationCode
    {
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now());
        $this->grants->save($code);

        return $code;
    }

    private function tokenOf(AuthorizationCode $code): string
    {
        return $this->tokens->issue(GrantedAuthorization::fromAuthorizationCode($code), Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }
}
