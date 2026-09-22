<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\UserInfo;

use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\UserInfo\UserInfoErrorResponse;
use Heidi\Oidc\Domain\UserInfo\UserInfoResponse;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class UserInfoResponseTest extends TestCase
{
    /**
     * OIDC Core §5.3.2: "sub" first, then the claims as JSON values of their kind; a "sub" a provider
     * would return is not the response's.
     */
    #[Test]
    public function itWritesSubFirstThenTheClaimsAsTheyAre(): void
    {
        // When
        $response = UserInfoResponse::json('alice-subject', [
            'email' => 'alice@acme.example',
            'sub' => 'someone-else',
            'email_verified' => true,
            'updated_at' => 1789466400,
            'address' => [
                'country' => 'FR',
            ],
        ]);

        // Then
        static::assertSame('alice-subject', $response->subject);
        static::assertSame([
            'sub' => 'alice-subject',
            'email' => 'alice@acme.example',
            'email_verified' => true,
            'updated_at' => 1789466400,
            'address' => [
                'country' => 'FR',
            ],
        ], $response->claims);
        static::assertSame('{"sub":"alice-subject","email":"alice@acme.example","email_verified":true,"updated_at":1789466400,"address":{"country":"FR"}}', $response->body);
        static::assertSame('application/json', $response->contentType);
    }

    #[Test]
    public function aResponseWithoutClaimsCarriesSubAlone(): void
    {
        // When / Then
        static::assertSame('{"sub":"alice-subject"}', UserInfoResponse::json('alice-subject', [])->body);
    }

    #[Test]
    public function itRefusesAnEmptySubject(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        UserInfoResponse::json('', []);
    }

    /**
     * RFC 6750 §3: the challenge carries "error" and "error_description"; the status is the exception's;
     * the body repeats the error.
     */
    #[Test]
    public function anInvalidTokenIsA401WithTheErrorInTheChallenge(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(new InvalidTokenException('The access token expired.'));

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertSame('invalid_token', $response->error);
        static::assertSame('The access token expired.', $response->errorDescription);
        static::assertNull($response->scope);
        static::assertSame('Bearer error="invalid_token", error_description="The access token expired."', $response->challenge());
        static::assertSame([
            'error' => 'invalid_token',
            'error_description' => 'The access token expired.',
        ], $response->parameters());
    }

    /**
     * RFC 6750 §3: nothing is cached.
     */
    #[Test]
    public function anErrorIsNotCached(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(new InvalidTokenException('The access token expired.'));

        // Then
        static::assertSame([
            'WWW-Authenticate' => 'Bearer error="invalid_token", error_description="The access token expired."',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ], $response->headers());
    }

    /**
     * RFC 6750 §3.1: invalid_request is a 400, through the same challenge.
     */
    #[Test]
    public function anInvalidRequestIsA400(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(new InvalidRequestException('The access token is sent by more than one method.'));

        // Then
        static::assertSame(400, $response->statusCode);
        static::assertSame('Bearer error="invalid_request", error_description="The access token is sent by more than one method."', $response->challenge());
    }

    /**
     * RFC 6750 §3: insufficient_scope is a 403 and the challenge names the scopes that would have done.
     */
    #[Test]
    public function anInsufficientScopeIsA403NamingTheScopes(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(new InsufficientScopeException('The token opens nothing here.', [Scope::openid(), new Scope('profile')]));

        // Then
        static::assertSame(403, $response->statusCode);
        static::assertSame('insufficient_scope', $response->error);
        static::assertSame('openid profile', $response->scope);
        static::assertSame('Bearer error="insufficient_scope", error_description="The token opens nothing here.", scope="openid profile"', $response->challenge());
        static::assertSame([
            'error' => 'insufficient_scope',
            'error_description' => 'The token opens nothing here.',
        ], $response->parameters());
    }

    /**
     * RFC 6750 §3.1: a request without any token gets the bare challenge, no error code, no body.
     */
    #[Test]
    public function aRequestWithoutTokenGetsTheBareChallenge(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(new MissingBearerTokenException());

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertNull($response->error);
        static::assertNull($response->errorDescription);
        static::assertNull($response->scope);
        static::assertSame('Bearer, DPoP', $response->challenge());
        static::assertSame([
            'WWW-Authenticate' => 'Bearer, DPoP',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ], $response->headers());
        static::assertSame([], $response->parameters());
    }

    /**
     * The description is optional in the challenge (RFC 6750 §3) and so in the body.
     */
    #[Test]
    public function theDescriptionIsOptional(): void
    {
        // When
        $response = new UserInfoErrorResponse(401, 'invalid_token', null);

        // Then
        static::assertSame('Bearer error="invalid_token"', $response->challenge());
        static::assertSame([
            'error' => 'invalid_token',
        ], $response->parameters());
    }
}
