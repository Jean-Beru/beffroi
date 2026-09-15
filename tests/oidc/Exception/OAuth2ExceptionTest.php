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
use Heidi\Oidc\Exception\RequestNotSupportedException;
use Heidi\Oidc\Exception\RequestUriNotSupportedException;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use Heidi\Oidc\Exception\UnsupportedResponseTypeException;
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
        $exception = new InvalidRequestException('The request is missing a parameter.');

        static::assertSame('invalid_request', $exception->error);
        static::assertSame('The request is missing a parameter.', $exception->errorDescription);
        static::assertSame(400, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertSame('invalid_request: The request is missing a parameter.', $exception->getMessage());
        static::assertSame(0, $exception->getCode(), 'the error is the code; the integer one means nothing');
        static::assertNull($exception->getPrevious());
        static::assertTrue(new InvalidRequestException('Sent back to the client.', true)->redirectable);

        $cause = new RuntimeException('What went wrong, for the logs.');
        static::assertSame($cause, new InvalidRequestException('Sent back to the client.', true, $cause)->getPrevious());
    }

    /**
     * RFC 6749 §5.2: invalid_client is answered 401, with WWW-Authenticate when the client used the
     * Authorization header; architecture §4.10 makes 401 the only status for it.
     */
    #[Test]
    public function anInvalidClientIsA401WithAnOptionalChallenge(): void
    {
        $bare = new InvalidClientException('Unknown client.');
        $challenged = new InvalidClientException('Unknown client.', 'Basic realm="https://id.acme.example"');

        static::assertSame('invalid_client', $bare->error);
        static::assertSame(401, $bare->statusCode);
        static::assertFalse($bare->redirectable);
        static::assertNull($bare->challenge);
        static::assertSame('Basic realm="https://id.acme.example"', $challenged->challenge);
    }

    /**
     * RFC 6749 §4.1.2.1 and §5.2: invalid_scope is raised by both endpoints, so the flag is the caller's;
     * the token endpoint answers 400.
     */
    #[Test]
    public function anInvalidScopeIsA400AndIsNotRedirectableByDefault(): void
    {
        $exception = new InvalidScopeException('The requested scope is not allowed for this client.');

        static::assertSame('invalid_scope', $exception->error);
        static::assertSame(400, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertTrue(new InvalidScopeException('Sent back to the client.', true)->redirectable);
    }

    /**
     * RFC 6749 §5.2: the errors of the token endpoint are 400 and never redirected; unauthorized_client
     * is also an error of the authorization endpoint (§4.1.2.1), so its flag is the caller's.
     */
    #[Test]
    public function theErrorsOfTheTokenEndpointAreA400AndAreNotRedirectable(): void
    {
        $exceptions = [
            'invalid_grant' => new InvalidGrantException('The authorization code is invalid.'),
            'unsupported_grant_type' => new UnsupportedGrantTypeException('The grant type is not supported by this provider.'),
            'unauthorized_client' => new UnauthorizedClientException('The client is not registered for this grant type.'),
        ];

        foreach ($exceptions as $error => $exception) {
            static::assertSame($error, $exception->error);
            static::assertSame(400, $exception->statusCode);
            static::assertFalse($exception->redirectable);
        }
        static::assertTrue(new UnauthorizedClientException('Sent back to the client.', true)->redirectable);

        $cause = new RuntimeException('What went wrong, for the logs.');
        static::assertSame($cause, new InvalidScopeException('Sent back to the client.', false, $cause)->getPrevious());
    }

    /**
     * RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6: the errors only the authorization endpoint raises, once
     * the client and its redirect URI are known, are always sent back to the client.
     */
    #[Test]
    public function theErrorsOfTheAuthorizationEndpointAloneAreAlwaysRedirectable(): void
    {
        $exceptions = [
            'unsupported_response_type' => new UnsupportedResponseTypeException('Only the code response type is supported.'),
            'request_not_supported' => new RequestNotSupportedException('Request objects are not supported.'),
            'request_uri_not_supported' => new RequestUriNotSupportedException('Request URIs are not supported.'),
            'login_required' => new LoginRequiredException('The end user is not authenticated.'),
            'consent_required' => new ConsentRequiredException('No consent covers the request.'),
            'access_denied' => new AccessDeniedException('The end user denied the request.'),
        ];

        foreach ($exceptions as $error => $exception) {
            static::assertSame($error, $exception->error);
            static::assertSame(400, $exception->statusCode);
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * RFC 6749 §5.2: error_description is ASCII text without double quotes nor backslashes.
     */
    #[Test]
    public function anErrorDescriptionOutsideTheAllowedCharactersIsAProgrammingError(): void
    {
        foreach (['', 'A "quoted" word', 'A back\\slash', 'Un accent aigu: é', "A line\nbreak"] as $description) {
            try {
                new InvalidRequestException($description);
                static::fail('The description should have been rejected.');
            } catch (InvalidArgumentException $exception) {
                static::assertStringContainsString('RFC 6749', $exception->getMessage());
            }
        }
    }

    /**
     * RFC 6750 §3.1: invalid_token is a 401 raised by a protected resource, never redirected; the cause
     * stays for the logs.
     */
    #[Test]
    public function anInvalidTokenIsA401(): void
    {
        $cause = new RuntimeException('What went wrong, for the logs.');
        $exception = new InvalidTokenException('The access token expired.', $cause);

        static::assertSame('invalid_token', $exception->error);
        static::assertSame('The access token expired.', $exception->errorDescription);
        static::assertSame(401, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertSame($cause, $exception->getPrevious());
        static::assertNull(new InvalidTokenException('The access token expired.')->getPrevious());
    }

    /**
     * RFC 6750 §3.1: insufficient_scope is a 403 that names the scopes the resource required.
     */
    #[Test]
    public function anInsufficientScopeIsA403NamingTheScopesRequired(): void
    {
        $exception = new InsufficientScopeException('The token does not open this resource.', [Scope::openid()]);

        static::assertSame('insufficient_scope', $exception->error);
        static::assertSame(403, $exception->statusCode);
        static::assertFalse($exception->redirectable);
        static::assertSame('openid', implode(' ', $exception->scopes));

        $this->expectException(InvalidArgumentException::class);
        new InsufficientScopeException('The token does not open this resource.', []);
    }

    /**
     * RFC 6750 §3.1: a request without any token is not an OAuth 2.0 error; it is a 401 without code.
     */
    #[Test]
    public function aMissingBearerTokenIsA401WithoutErrorCode(): void
    {
        $exception = new MissingBearerTokenException();

        static::assertSame('The request carries no bearer token.', $exception->getMessage());
        static::assertSame(0, $exception->getCode());
        static::assertNull($exception->getPrevious());
    }
}
