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
        $claims = new ClaimsRequest([], [
            'email' => new ClaimRequest(true),
        ]);
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile'], 'n-0S6_WzA2Mj', $claims);

        $authorization = GrantedAuthorization::fromAuthorizationCode($code);

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
        static::assertNull($authorization->authenticationContextClass);
        static::assertTrue($authorization->hasScope(new Scope('profile')));
        static::assertFalse($authorization->hasScope(new Scope('email')));
    }

    /**
     * RFC 6749 §6, OIDC Core §12.2: after a refresh, the scopes are those of the token or the narrower
     * ones asked for, the token's scopes stay the granted ones, and there is no nonce.
     */
    #[Test]
    public function fromARefreshTokenItNarrowsTheScopesAndDropsTheNonce(): void
    {
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile', 'email']);

        $whole = GrantedAuthorization::fromRefreshToken($token, null);
        $narrowed = GrantedAuthorization::fromRefreshToken($token, [new Scope('profile')]);

        static::assertSame(GrantType::RefreshToken, $whole->grantType);
        static::assertSame($token->scopes, $whole->scopes);
        static::assertSame($token->scopes, $whole->grantedScopes);
        static::assertNull($whole->nonce);
        static::assertEquals([new Scope('profile')], $narrowed->scopes);
        static::assertSame($token->scopes, $narrowed->grantedScopes);
        static::assertFalse($narrowed->hasScope(Scope::openid()));
        static::assertSame($token->client, $narrowed->client);
        static::assertSame($token->session, $narrowed->session);
        static::assertEquals($token->authenticatedAt, $narrowed->authenticatedAt);
        static::assertSame($token->authenticationMethods, $narrowed->authenticationMethods);
    }

    #[Test]
    public function itRefusesAScopeOutsideTheGrantedOnes(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->authorization(scopes: [Scope::openid(), new Scope('email')], grantedScopes: [Scope::openid()]);
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->authorization(scopes: [], grantedScopes: [Scope::openid()]);
    }

    #[Test]
    public function itRefusesAnEmptyGrantedScopeList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->authorization(scopes: [Scope::openid()], grantedScopes: []);
    }

    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->authorization(methods: []);
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->authorization(client: Clients::public(Fixtures::tenant('other', 'https://id.other.example')));
    }

    /**
     * OIDC Core §12.2: an ID token issued on a refresh carries no nonce.
     */
    #[Test]
    public function itRefusesANonceOnARefresh(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->authorization(grantType: GrantType::RefreshToken, nonce: 'n-0S6_WzA2Mj');
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
            null,
        );
    }
}
