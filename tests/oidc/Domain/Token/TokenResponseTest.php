<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\TokenErrorResponse;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidGrantException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class TokenResponseTest extends TestCase
{
    /**
     * RFC 6749 §5.1: the members in order, "token_type" always Bearer (RFC 6750), "scope" always given,
     * and the headers that keep the credentials out of every cache.
     */
    #[Test]
    public function itWritesTheMembersOfRfc6749Section51InOrder(): void
    {
        $response = new TokenResponse('at.value', 600, 'rt.value', 'id.value', [Scope::openid(), new Scope('profile')]);

        static::assertSame([
            'access_token' => 'at.value',
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'refresh_token' => 'rt.value',
            'id_token' => 'id.value',
            'scope' => 'openid profile',
        ], $response->parameters());
        static::assertSame([
            'access_token' => 'at.value',
            'token_type' => 'Bearer',
            'expires_in' => 600,
            'scope' => 'openid',
        ], new TokenResponse('at.value', 600, null, null, [Scope::openid()])->parameters());
    }

    #[Test]
    public function itRefusesAnEmptyAccessToken(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new TokenResponse('', 600, null, null, [Scope::openid()]);
    }

    #[Test]
    public function itRefusesAnEmptyRefreshOrIdToken(): void
    {
        foreach ([['', null], [null, '']] as [$refreshToken, $idToken]) {
            try {
                new TokenResponse('at.value', 600, $refreshToken, $idToken, [Scope::openid()]);
                static::fail('The response should have been refused.');
            } catch (InvalidArgumentException $exception) {
                static::assertStringContainsString('absent or non-empty', $exception->getMessage());
            }
        }
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new TokenResponse('at.value', 600, null, null, []);
    }

    /**
     * RFC 6749 §5.2: "error" and "error_description" as JSON, 400, the same no-store headers.
     */
    #[Test]
    public function anErrorIsWrittenAsRfc6749Section52Says(): void
    {
        $response = TokenErrorResponse::fromException(new InvalidGrantException('The authorization code is invalid.'));

        static::assertSame(400, $response->statusCode);
        static::assertSame('invalid_grant', $response->error);
        static::assertSame('The authorization code is invalid.', $response->errorDescription);
        static::assertNull($response->challenge);
        static::assertSame([
            'error' => 'invalid_grant',
            'error_description' => 'The authorization code is invalid.',
        ], $response->parameters());
        static::assertSame([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ], $response->headers());
    }

    /**
     * RFC 6749 §5.2: 401 and WWW-Authenticate when the client used the Authorization header.
     */
    #[Test]
    public function anInvalidClientCarriesItsChallenge(): void
    {
        $challenged = TokenErrorResponse::fromException(new InvalidClientException('Client authentication failed.', 'Basic realm="https://id.acme.example"'));
        $bare = TokenErrorResponse::fromException(new InvalidClientException('Client authentication failed.'));

        static::assertSame(401, $challenged->statusCode);
        static::assertSame('Basic realm="https://id.acme.example"', $challenged->challenge);
        static::assertSame([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
            'WWW-Authenticate' => 'Basic realm="https://id.acme.example"',
        ], $challenged->headers());
        static::assertSame(401, $bare->statusCode);
        static::assertNull($bare->challenge);
        static::assertArrayNotHasKey('WWW-Authenticate', $bare->headers());
    }
}
