<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Exception;

use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\RequestNotSupportedException;
use Heidi\Oidc\Exception\RequestUriNotSupportedException;
use Heidi\Oidc\Exception\UnsupportedResponseTypeException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
        static::assertTrue(new InvalidRequestException('Sent back to the client.', true)->redirectable);
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
}
