<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class UserAuthorizationTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    /**
     * RFC 6749 §4.1.3, OIDC Core §3.1.3: after a code, the tokens carry what the code recorded, nonce
     * included.
     */
    #[Test]
    public function fromACodeItCarriesEverythingTheCodeRecorded(): void
    {
        // Given
        $claims = new ClaimsRequest([], [
            'email' => new ClaimRequest(true),
        ]);
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile'], 'n-0S6_WzA2Mj', $claims);

        // When
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code);

        // Then
        static::assertTrue($authorization->grantType->equals(Grants::authorizationCode()));
        static::assertSame($this->client, $authorization->client);
        static::assertSame($this->session, $authorization->session);
        static::assertSame($this->session->tenant, $authorization->tenant);
        static::assertSame($this->session->user, $authorization->user);
        static::assertSame($code->scopes, $authorization->scopes);
        static::assertSame($code->scopes, $authorization->grantedScopes);
        static::assertSame('n-0S6_WzA2Mj', $authorization->nonce);
        static::assertSame($claims, $authorization->claimsRequest);
        static::assertEquals($this->session->authenticatedAt(), $authorization->authentication->authenticatedAt);
        static::assertSame(['pwd'], $authorization->authentication->methods);
        static::assertSame('1', $authorization->authentication->contextClass);
    }

    #[Test]
    public function itKnowsTheScopesItCarries(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'profile'],
        ));

        // When / Then
        static::assertTrue($authorization->scopes->has(new Scope('profile')));
        static::assertFalse($authorization->scopes->has(new Scope('email')));
    }

    /**
     * RFC 6749 §6, OIDC Core §12.2: after a refresh without a scope, the scopes are those of the token,
     * and there is no nonce.
     */
    #[Test]
    public function fromARefreshTokenItKeepsTheScopesOfTheTokenAndDropsTheNonce(): void
    {
        // Given
        $token = $this->refreshToken();

        // When
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, null);

        // Then
        static::assertTrue($authorization->grantType->equals(Grants::refreshToken()));
        static::assertSame($token->scopes, $authorization->scopes);
        static::assertSame($token->scopes, $authorization->grantedScopes);
        static::assertNull($authorization->nonce);
    }

    /**
     * RFC 6749 §6: after a refresh with a scope, the scopes are the narrower ones asked for and the
     * token's scopes stay the granted ones.
     */
    #[Test]
    public function fromARefreshTokenItNarrowsTheScopesToThoseAskedFor(): void
    {
        // Given
        $token = $this->refreshToken();

        // When
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));

        // Then
        static::assertEquals([new Scope('profile')], $authorization->scopes->all);
        static::assertSame($token->scopes, $authorization->grantedScopes);
        static::assertFalse($authorization->scopes->has(Scope::openid()));
    }

    #[Test]
    public function fromARefreshTokenItCarriesTheAuthenticationOfTheToken(): void
    {
        // Given
        $token = $this->refreshToken();

        // When
        $authorization = UserAuthorization::fromRefreshToken(Grants::refreshToken(), $token, new Scopes([new Scope('profile')]));

        // Then
        static::assertSame($token->client, $authorization->client);
        static::assertSame($token->session, $authorization->session);
        static::assertEquals($token->authentication->authenticatedAt, $authorization->authentication->authenticatedAt);
        static::assertSame($token->authentication->methods, $authorization->authentication->methods);
    }

    #[Test]
    public function itRefusesAScopeOutsideTheGrantedOnes(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(scopes: new Scopes([Scope::openid(), new Scope('email')]), grantedScopes: new Scopes([Scope::openid()]));
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(client: Clients::public(Fixtures::tenant('other', 'https://id.other.example')));
    }

    private function refreshToken(): RefreshToken
    {
        return Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile', 'email']);
    }

    /**
     * @param list<string>|null $methods
     */
    private function authorization(
        ?GrantTypeName $grantType = null,
        ?Client $client = null,
        ?Scopes $scopes = null,
        ?Scopes $grantedScopes = null,
        ?string $nonce = null,
        ?array $methods = null,
    ): UserAuthorization {
        return new UserAuthorization(
            $grantType ?? Grants::authorizationCode(),
            Uuid::v7(),
            $client ?? $this->client,
            $this->session,
            $scopes ?? new Scopes([Scope::openid()]),
            $grantedScopes ?? new Scopes([Scope::openid()]),
            $nonce,
            null,
            new AuthenticationSnapshot(
                $this->session->authenticatedAt(),
                $methods ?? $this->session->methodReferences(),
                $this->session->authenticationContextClass()->value,
            ),
        );
    }
}
