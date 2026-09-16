<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class GrantedAuthorizationTest extends TestCase
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
        $authorization = GrantedAuthorization::fromAuthorizationCode($code);

        // Then
        static::assertSame(GrantType::AuthorizationCode, $authorization->grantType);
        static::assertSame($this->client, $authorization->client);
        static::assertSame($this->session, $authorization->session);
        static::assertSame($this->session->tenant, $authorization->tenant);
        static::assertSame($this->session->user, $authorization->user);
        static::assertSame($code->scopes, $authorization->scopes);
        static::assertSame($code->scopes, $authorization->grantedScopes);
        static::assertSame('n-0S6_WzA2Mj', $authorization->nonce);
        static::assertSame($claims, $authorization->claimsRequest);
        static::assertEquals($this->session->authenticatedAt(), $authorization->authenticatedAt);
        static::assertSame(['pwd'], $authorization->authenticationMethods);
        static::assertSame('1', $authorization->authenticationContextClass);
    }

    #[Test]
    public function itKnowsTheScopesItCarries(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile']));

        // When / Then
        static::assertTrue($authorization->hasScope(new Scope('profile')));
        static::assertFalse($authorization->hasScope(new Scope('email')));
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
        $authorization = GrantedAuthorization::fromRefreshToken($token, null);

        // Then
        static::assertSame(GrantType::RefreshToken, $authorization->grantType);
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
        $authorization = GrantedAuthorization::fromRefreshToken($token, [new Scope('profile')]);

        // Then
        static::assertEquals([new Scope('profile')], $authorization->scopes);
        static::assertSame($token->scopes, $authorization->grantedScopes);
        static::assertFalse($authorization->hasScope(Scope::openid()));
    }

    #[Test]
    public function fromARefreshTokenItCarriesTheAuthenticationOfTheToken(): void
    {
        // Given
        $token = $this->refreshToken();

        // When
        $authorization = GrantedAuthorization::fromRefreshToken($token, [new Scope('profile')]);

        // Then
        static::assertSame($token->client, $authorization->client);
        static::assertSame($token->session, $authorization->session);
        static::assertEquals($token->authenticatedAt, $authorization->authenticatedAt);
        static::assertSame($token->authenticationMethods, $authorization->authenticationMethods);
    }

    #[Test]
    public function itRefusesAScopeOutsideTheGrantedOnes(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(scopes: [Scope::openid(), new Scope('email')], grantedScopes: [Scope::openid()]);
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(scopes: [], grantedScopes: [Scope::openid()]);
    }

    #[Test]
    public function itRefusesAnEmptyGrantedScopeList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(scopes: [Scope::openid()], grantedScopes: []);
    }

    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(methods: []);
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(client: Clients::public(Fixtures::tenant('other', 'https://id.other.example')));
    }

    /**
     * OIDC Core §12.2: an ID token issued on a refresh carries no nonce.
     */
    #[Test]
    public function itRefusesANonceOnARefresh(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->authorization(grantType: GrantType::RefreshToken, nonce: 'n-0S6_WzA2Mj');
    }

    private function refreshToken(): RefreshToken
    {
        return Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile', 'email']);
    }

    /**
     * @param list<Scope>|null $scopes
     * @param list<Scope>|null $grantedScopes
     * @param list<string>|null $methods
     */
    private function authorization(GrantType $grantType = GrantType::AuthorizationCode, ?Client $client = null, ?array $scopes = null, ?array $grantedScopes = null, ?string $nonce = null, ?array $methods = null): GrantedAuthorization
    {
        return new GrantedAuthorization(
            $grantType,
            $client ?? $this->client,
            $this->session,
            $scopes ?? [Scope::openid()],
            $grantedScopes ?? [Scope::openid()],
            $nonce,
            null,
            $this->session->authenticatedAt(),
            $methods ?? $this->session->methodReferences(),
            $this->session->authenticationContextClass()
                ->value,
        );
    }
}
