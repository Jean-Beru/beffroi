<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Domain\Token\IssuedRefreshToken;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class IssuedTokensTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private UserAuthorization $authorization;

    private AccessToken $accessToken;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'profile'],
        ));
        $this->accessToken = new AccessToken('at.value', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * RFC 8693 §2.2.1: the grant that exchanged them says the type it issued, and the response carries it.
     */
    #[Test]
    public function theTypeAGrantSaysItIssuedReachesTheResponse(): void
    {
        // Given
        $issued = new IssuedTokens($this->authorization, $this->accessToken, null, null);

        // When
        $response = $issued->withIssuedTokenType(TokenTypeIdentifier::accessToken())->toResponse();

        // Then
        static::assertSame('urn:ietf:params:oauth:token-type:access_token', $response->parameters()['issued_token_type']);
    }

    /**
     * RFC 6749 §5.1: a grant with no type to name names none.
     */
    #[Test]
    public function aGrantWithNoTypeToNameNamesNone(): void
    {
        // Given
        $issued = new IssuedTokens($this->authorization, $this->accessToken, null, null);

        // When
        $response = $issued->toResponse();

        // Then
        static::assertArrayNotHasKey('issued_token_type', $response->parameters());
    }

    /**
     * RFC 6749 §5.1, OIDC Core §3.1.3.3: the response carries every token issued and the scopes.
     */
    #[Test]
    public function itBecomesTheResponseWithEveryTokenIssued(): void
    {
        // Given
        $refreshToken = new IssuedRefreshToken(Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now()), 'rt.value');
        $issued = new IssuedTokens($this->authorization, $this->accessToken, 'id.value', $refreshToken);

        // When
        $response = $issued->toResponse();

        // Then
        static::assertSame(
            [
                'access_token' => 'at.value',
                'token_type' => 'Bearer',
                'expires_in' => 600,
                'refresh_token' => 'rt.value',
                'id_token' => 'id.value',
                'scope' => 'openid profile',
            ],
            $response->parameters(),
        );
        static::assertSame($this->authorization->scopes, $response->scopes);
    }

    #[Test]
    public function itBecomesTheResponseWithoutWhatWasNotIssued(): void
    {
        // Given
        $issued = new IssuedTokens($this->authorization, $this->accessToken, null, null);

        // When
        $response = $issued->toResponse();

        // Then
        static::assertSame(
            [
                'access_token' => 'at.value',
                'token_type' => 'Bearer',
                'expires_in' => 600,
                'scope' => 'openid profile',
            ],
            $response->parameters(),
        );
    }

    #[Test]
    public function itRefusesAnEmptyIdToken(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new IssuedTokens($this->authorization, $this->accessToken, '', null);
    }

    #[Test]
    public function aRefreshTokenIsARecordAndItsValue(): void
    {
        // Given
        $token = Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now());

        // When
        $issued = new IssuedRefreshToken($token, 'rt.value');

        // Then
        static::assertSame($token, $issued->token);
        static::assertSame('rt.value', $issued->value);
    }

    /**
     * The record is the hash of the value: the two sides of a refresh token never drift apart.
     */
    #[Test]
    public function aRefreshTokenRefusesAValueThatIsNotTheOneRecorded(): void
    {
        // Given
        $token = Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new IssuedRefreshToken($token, 'another');
    }

    /**
     * RFC 9396 §7: the response says what the authorization granted beyond its scopes, which is what a client
     * holding an opaque access token would otherwise have to introspect its own token to learn.
     */
    #[Test]
    public function theDetailsOfTheAuthorizationReachTheResponse(): void
    {
        // Given
        $withDetails = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid'],
            authorizationDetails: AuthorizationDetailTypes::details(),
        ));
        $issued = new IssuedTokens($withDetails, $this->accessToken, null, null);

        // When
        $response = $issued->toResponse();

        // Then
        static::assertSame(
            [
                [
                    'type' => 'account_information',
                    'account' => 'acct-4711',
                    'actions' => ['read'],
                ],
            ],
            $response->parameters()['authorization_details'],
        );
    }

    /**
     * RFC 9396 §7: an authorization that granted none says nothing of them.
     */
    #[Test]
    public function anAuthorizationWithNoDetailWritesNoMember(): void
    {
        // Given
        $issued = new IssuedTokens($this->authorization, $this->accessToken, null, null);

        // When
        $response = $issued->toResponse();

        // Then
        static::assertArrayNotHasKey('authorization_details', $response->parameters());
    }

    #[Test]
    public function theScopesOfTheResponseAreThoseOfTheAuthorization(): void
    {
        // Given
        $narrowed = UserAuthorization::fromRefreshToken(
            Grants::refreshToken(),
            Tokens::refreshToken('rt.value', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']),
            new Scopes([new Scope('profile')]),
        );
        $issued = new IssuedTokens($narrowed, $this->accessToken, null, null);

        // When
        $response = $issued->toResponse();

        // Then
        static::assertSame('profile', $response->parameters()['scope']);
    }
}
