<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\IssuedRefreshToken;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class IssuedTokensTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private GrantedAuthorization $authorization;

    private AccessToken $accessToken;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile']));
        $this->accessToken = new AccessToken('at.value', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * RFC 6749 §5.1, OIDC Core §3.1.3.3: the response carries every token issued and the scopes.
     */
    #[Test]
    public function itBecomesTheResponseWithEveryTokenIssued(): void
    {
        $refreshToken = new IssuedRefreshToken(Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now()), 'rt.value');

        $response = new IssuedTokens($this->authorization, $this->accessToken, 'id.value', $refreshToken)
            ->toResponse();

        static::assertSame([
            'access_token' => 'at.value',
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'refresh_token' => 'rt.value',
            'id_token' => 'id.value',
            'scope' => 'openid profile',
        ], $response->parameters());
        static::assertSame($this->authorization->scopes, $response->scopes);
    }

    #[Test]
    public function itBecomesTheResponseWithoutWhatWasNotIssued(): void
    {
        $response = new IssuedTokens($this->authorization, $this->accessToken, null, null)
            ->toResponse();

        static::assertSame([
            'access_token' => 'at.value',
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'scope' => 'openid profile',
        ], $response->parameters());
    }

    #[Test]
    public function itRefusesAnEmptyIdToken(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new IssuedTokens($this->authorization, $this->accessToken, '', null);
    }

    /**
     * The record is the hash of the value: the two sides of a refresh token never drift apart.
     */
    #[Test]
    public function aRefreshTokenIsARecordAndItsValue(): void
    {
        $token = Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now());

        $issued = new IssuedRefreshToken($token, 'rt.value');

        static::assertSame($token, $issued->token);
        static::assertSame('rt.value', $issued->value);

        $this->expectException(InvalidArgumentException::class);
        new IssuedRefreshToken($token, 'another');
    }

    #[Test]
    public function theScopesOfTheResponseAreThoseOfTheAuthorization(): void
    {
        $narrowed = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']), [new Scope('profile')]);

        $response = new IssuedTokens($narrowed, $this->accessToken, null, null)
            ->toResponse();

        static::assertSame('profile', $response->parameters()['scope']);
    }
}
