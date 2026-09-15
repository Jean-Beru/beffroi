<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Exception;

use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\AccessDeniedException;
use Heidi\Oidc\Exception\ConsentRequiredException;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Exception\LoginRequiredException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\RequestNotSupportedException;
use Heidi\Oidc\Exception\RequestUriNotSupportedException;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use Heidi\Oidc\Exception\UnsupportedResponseTypeException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class OAuth2ExceptionTest extends TestCase
{
    /**
     * RFC 6749 §5.2: invalid_request is a 400; the flag says whether the authorization endpoint may
     * redirect it, which the token endpoint never does.
     */
    #[Test]
    public function anInvalidRequestIsA400AndIsNotRedirectableByDefault(): void
    {
        // When
        $exception = new InvalidRequestException('The request is missing a parameter.');

        // Then
        static::assertSame('invalid_request', $exception->error);
        static::assertSame('The request is missing a parameter.', $exception->errorDescription);
        static::assertSame(400, $exception->statusCode);
        static::assertFalse($exception->redirectable);
    }

    /**
     * The message is the error and its description; the error is the code, the integer one means nothing.
     */
    #[Test]
    public function theMessageIsTheErrorAndItsDescription(): void
    {
        // When
        $exception = new InvalidRequestException('The request is missing a parameter.');

        // Then
        static::assertSame('invalid_request: The request is missing a parameter.', $exception->getMessage());
        static::assertSame(0, $exception->getCode());
        static::assertNull($exception->getPrevious());
    }

    #[Test]
    public function anInvalidRequestMayBeRedirectable(): void
    {
        // When
        $exception = new InvalidRequestException('Sent back to the client.', true);

        // Then
        static::assertTrue($exception->redirectable);
    }

    /**
     * The cause stays for the logs.
     */
    #[Test]
    #[DataProvider('provideExceptionsWithACause')]
    public function theCauseStaysForTheLogs(callable $build): void
    {
        // Given
        $cause = new RuntimeException('What went wrong, for the logs.');

        // When
        $exception = $build($cause);

        // Then
        static::assertInstanceOf(OAuth2Exception::class, $exception);
        static::assertSame($cause, $exception->getPrevious());
    }

    /**
     * @return iterable<string, array{callable(RuntimeException): OAuth2Exception}>
     */
    public static function provideExceptionsWithACause(): iterable
    {
        yield 'invalid_request' => [
            static fn (RuntimeException $cause): OAuth2Exception => new InvalidRequestException('Sent back to the client.', true, $cause),
        ];
        yield 'invalid_scope' => [
            static fn (RuntimeException $cause): OAuth2Exception => new InvalidScopeException('Sent back to the client.', false, $cause),
        ];
        yield 'invalid_token' => [
            static fn (RuntimeException $cause): OAuth2Exception => new InvalidTokenException('The access token expired.', $cause),
        ];
    }

    /**
     * RFC 6749 §5.2: invalid_client is answered 401; architecture §4.10 makes 401 the only status for it.
     */
    #[Test]
    public function anInvalidClientIsA401WithoutChallengeByDefault(): void
    {
        // When
        $exception = new InvalidClientException('Unknown client.');

        // Then
        static::assertSame('invalid_client', $exception->error);
        static::assertSame(401, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertNull($exception->challenge);
    }

    /**
     * RFC 6749 §5.2: WWW-Authenticate when the client used the Authorization header.
     */
    #[Test]
    public function anInvalidClientMayCarryAChallenge(): void
    {
        // When
        $exception = new InvalidClientException('Unknown client.', 'Basic realm="https://id.acme.example"');

        // Then
        static::assertSame('Basic realm="https://id.acme.example"', $exception->challenge);
    }

    /**
     * RFC 6749 §4.1.2.1 and §5.2: invalid_scope is raised by both endpoints, so the flag is the caller's;
     * the token endpoint answers 400.
     */
    #[Test]
    public function anInvalidScopeIsA400AndIsNotRedirectableByDefault(): void
    {
        // When
        $exception = new InvalidScopeException('The requested scope is not allowed for this client.');

        // Then
        static::assertSame('invalid_scope', $exception->error);
        static::assertSame(400, $exception->statusCode);
        static::assertFalse($exception->redirectable);
    }

    /**
     * RFC 6749 §5.2: the errors of the token endpoint are 400 and never redirected.
     */
    #[Test]
    #[DataProvider('provideErrorsOfTheTokenEndpoint')]
    public function theErrorsOfTheTokenEndpointAreA400AndAreNotRedirectable(string $error, OAuth2Exception $exception): void
    {
        // When / Then
        static::assertSame($error, $exception->error);
        static::assertSame(400, $exception->statusCode);
        static::assertFalse($exception->redirectable);
    }

    /**
     * @return iterable<string, array{string, OAuth2Exception}>
     */
    public static function provideErrorsOfTheTokenEndpoint(): iterable
    {
        yield 'invalid_grant' => ['invalid_grant', new InvalidGrantException('The authorization code is invalid.')];
        yield 'unsupported_grant_type' => ['unsupported_grant_type', new UnsupportedGrantTypeException('The grant type is not supported by this provider.')];
        yield 'unauthorized_client' => ['unauthorized_client', new UnauthorizedClientException('The client is not registered for this grant type.')];
    }

    /**
     * RFC 6749 §4.1.2.1: invalid_scope and unauthorized_client are also errors of the authorization
     * endpoint, so their flag is the caller's.
     */
    #[Test]
    #[DataProvider('provideErrorsOfBothEndpoints')]
    public function theErrorsOfBothEndpointsMayBeRedirectable(OAuth2Exception $exception): void
    {
        // When / Then
        static::assertTrue($exception->redirectable);
    }

    /**
     * @return iterable<string, array{OAuth2Exception}>
     */
    public static function provideErrorsOfBothEndpoints(): iterable
    {
        yield 'invalid_scope' => [new InvalidScopeException('Sent back to the client.', true)];
        yield 'unauthorized_client' => [new UnauthorizedClientException('Sent back to the client.', true)];
    }

    /**
     * RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6: the errors only the authorization endpoint raises, once
     * the client and its redirect URI are known, are always sent back to the client.
     */
    #[Test]
    #[DataProvider('provideErrorsOfTheAuthorizationEndpointAlone')]
    public function theErrorsOfTheAuthorizationEndpointAloneAreAlwaysRedirectable(string $error, OAuth2Exception $exception): void
    {
        // When / Then
        static::assertSame($error, $exception->error);
        static::assertSame(400, $exception->statusCode);
        static::assertTrue($exception->redirectable);
    }

    /**
     * @return iterable<string, array{string, OAuth2Exception}>
     */
    public static function provideErrorsOfTheAuthorizationEndpointAlone(): iterable
    {
        yield 'unsupported_response_type' => ['unsupported_response_type', new UnsupportedResponseTypeException('Only the code response type is supported.')];
        yield 'request_not_supported' => ['request_not_supported', new RequestNotSupportedException('Request objects are not supported.')];
        yield 'request_uri_not_supported' => ['request_uri_not_supported', new RequestUriNotSupportedException('Request URIs are not supported.')];
        yield 'login_required' => ['login_required', new LoginRequiredException('The end user is not authenticated.')];
        yield 'consent_required' => ['consent_required', new ConsentRequiredException('No consent covers the request.')];
        yield 'access_denied' => ['access_denied', new AccessDeniedException('The end user denied the request.')];
    }

    /**
     * RFC 6749 §5.2: error_description is ASCII text without double quotes nor backslashes.
     */
    #[Test]
    #[DataProvider('provideForbiddenDescriptions')]
    public function anErrorDescriptionOutsideTheAllowedCharactersIsAProgrammingError(string $description): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('RFC 6749');

        // When
        new InvalidRequestException($description);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideForbiddenDescriptions(): iterable
    {
        yield 'empty' => [''];
        yield 'double quotes' => ['A "quoted" word'];
        yield 'backslash' => ['A back\\slash'];
        yield 'beyond ASCII' => ['Un accent aigu: é'];
        yield 'line break' => ["A line\nbreak"];
    }

    /**
     * RFC 6750 §3.1: invalid_token is a 401 raised by a protected resource, never redirected.
     */
    #[Test]
    public function anInvalidTokenIsA401(): void
    {
        // When
        $exception = new InvalidTokenException('The access token expired.');

        // Then
        static::assertSame('invalid_token', $exception->error);
        static::assertSame('The access token expired.', $exception->errorDescription);
        static::assertSame(401, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertNull($exception->getPrevious());
    }

    /**
     * RFC 6750 §3.1: insufficient_scope is a 403 that names the scopes the resource required.
     */
    #[Test]
    public function anInsufficientScopeIsA403NamingTheScopesRequired(): void
    {
        // When
        $exception = new InsufficientScopeException('The token does not open this resource.', [Scope::openid()]);

        // Then
        static::assertSame('insufficient_scope', $exception->error);
        static::assertSame(403, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertSame('openid', implode(' ', $exception->scopes));
    }

    #[Test]
    public function anInsufficientScopeNamesAtLeastOneScope(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new InsufficientScopeException('The token does not open this resource.', []);
    }

    /**
     * RFC 6750 §3.1: a request without any token is not an OAuth 2.0 error; it is a 401 without code.
     */
    #[Test]
    public function aMissingBearerTokenIsA401WithoutErrorCode(): void
    {
        // When
        $exception = new MissingBearerTokenException();

        // Then
        static::assertSame('The request carries no bearer token.', $exception->getMessage());
        static::assertSame(0, $exception->getCode());
        static::assertNull($exception->getPrevious());
    }
}
