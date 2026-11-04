<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\TokenErrorResponse;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class TokenResponseTest extends TestCase
{
    /**
     * RFC 6749 §5.1, RFC 6750
     */
    #[Test]
    public function itWritesTheMembersOfRfc6749Section51InOrder(): void
    {
        // When
        $response = new TokenResponse('at.value', 600, 'rt.value', 'id.value', new Scopes([Scope::openid(), new Scope('profile')]));

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
    }

    /**
     * RFC 8693 §2.2.1
     */
    #[Test]
    public function aResponseOfAnExchangeNamesTheTypeOfTheTokenItIssued(): void
    {
        // When
        $response = new TokenResponse(
            'at.value',
            600,
            null,
            null,
            new Scopes([new Scope('invoices.read')]),
            TokenResponse::BEARER,
            TokenTypeIdentifier::accessToken(),
        );

        // Then
        static::assertSame(
            [
                'access_token' => 'at.value',
                'token_type' => 'Bearer',
                'expires_in' => 600,
                'issued_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
                'scope' => 'invoices.read',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aResponseThatGrantedDetailsSaysWhichOnesItGranted(): void
    {
        // When
        $response = new TokenResponse(
            'at.value',
            600,
            null,
            null,
            new Scopes([Scope::openid()]),
            TokenResponse::BEARER,
            null,
            AuthorizationDetailTypes::details(),
        );

        // Then
        static::assertSame(
            [
                'access_token' => 'at.value',
                'token_type' => 'Bearer',
                'expires_in' => 600,
                'scope' => 'openid',
                'authorization_details' => [
                    [
                        'type' => 'account_information',
                        'account' => 'acct-4711',
                        'actions' => ['read'],
                    ],
                ],
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aResponseThatGrantedNoDetailWritesNoMember(): void
    {
        // When
        $response = new TokenResponse('at.value', 600, null, null, new Scopes([Scope::openid()]));

        // Then
        static::assertArrayNotHasKey('authorization_details', $response->parameters());
    }

    /**
     * RFC 6749 §5.1
     */
    #[Test]
    public function aResponseNoExchangeProducedNamesNoIssuedTokenType(): void
    {
        // When
        $response = new TokenResponse('at.value', 600, null, null, new Scopes([Scope::openid()]));

        // Then
        static::assertArrayNotHasKey('issued_token_type', $response->parameters());
    }

    #[Test]
    public function itOmitsTheTokensThatWereNotIssued(): void
    {
        // When
        $response = new TokenResponse('at.value', 600, null, null, new Scopes([Scope::openid()]));

        // Then
        static::assertSame(
            [
                'access_token' => 'at.value',
                'token_type' => 'Bearer',
                'expires_in' => 600,
                'scope' => 'openid',
            ],
            $response->parameters(),
        );
    }

    #[Test]
    public function itRefusesAnEmptyAccessToken(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new TokenResponse('', 600, null, null, new Scopes([Scope::openid()]));
    }

    #[Test]
    #[DataProvider('provideEmptyOptionalTokens')]
    public function itRefusesAnEmptyRefreshOrIdToken(?string $refreshToken, ?string $idToken): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('absent or non-empty');

        // When
        new TokenResponse('at.value', 600, $refreshToken, $idToken, new Scopes([Scope::openid()]));
    }

    /**
     * @return iterable<string, array{?string, ?string}>
     */
    public static function provideEmptyOptionalTokens(): iterable
    {
        yield 'empty refresh token' => ['', null];
        yield 'empty ID token' => [null, ''];
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function anErrorIsWrittenAsRfc6749Section52Says(): void
    {
        // When
        $response = TokenErrorResponse::fromException(new InvalidGrantException('The authorization code is invalid.'));

        // Then
        static::assertSame(400, $response->statusCode);
        static::assertSame('invalid_grant', $response->error);
        static::assertSame('The authorization code is invalid.', $response->errorDescription);
        static::assertNull($response->challenge);
        static::assertSame(
            [
                'error' => 'invalid_grant',
                'error_description' => 'The authorization code is invalid.',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 6749 §5.1, §5.2
     */
    #[Test]
    public function anErrorIsNotCached(): void
    {
        // When
        $response = TokenErrorResponse::fromException(new InvalidGrantException('The authorization code is invalid.'));

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            $response->headers(),
        );
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function anInvalidClientCarriesItsChallenge(): void
    {
        // When
        $response = TokenErrorResponse::fromException(new InvalidClientException('Client authentication failed.', 'Basic realm="https://id.acme.example"'));

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertSame('Basic realm="https://id.acme.example"', $response->challenge);
        static::assertSame(
            [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'WWW-Authenticate' => 'Basic realm="https://id.acme.example"',
            ],
            $response->headers(),
        );
    }

    #[Test]
    public function anInvalidClientWithoutChallengeIsA401WithoutWwwAuthenticate(): void
    {
        // When
        $response = TokenErrorResponse::fromException(new InvalidClientException('Client authentication failed.'));

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertNull($response->challenge);
        static::assertArrayNotHasKey('WWW-Authenticate', $response->headers());
    }
}
