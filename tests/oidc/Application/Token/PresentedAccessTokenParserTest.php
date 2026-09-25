<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Application\Token\PresentedAccessTokenParser;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\Bindings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PresentedAccessTokenParserTest extends TestCase
{
    private const string JWS = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmFjbWUuZXhhbXBsZSJ9.c2ln';

    private PresentedAccessTokenParser $parser;

    protected function setUp(): void
    {
        $this->parser = new PresentedAccessTokenParser(Bindings::wired());
    }

    /**
     * RFC 6750 §2.1: "Bearer" then the b64token, the scheme compared without regard to case (RFC 9110
     * §11.1); RFC 9449 §7.1: "DPoP" then the same, for a token bound to a key; RFC 6750 §2.2: the
     * "access_token" form parameter, which carries a bearer token and only one. Each alone is the token.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideOneMethod')]
    public function itReadsTheTokenFromTheHeaderOrTheBody(?string $header, array $parameters, string $expected, string $scheme = TokenResponse::BEARER): void
    {
        // When
        $token = $this->parser->parse($header, RequestParameters::of($parameters));

        // Then
        static::assertNotNull($token);
        static::assertSame($expected, $token->value);
        static::assertSame($scheme, $token->scheme);
    }

    /**
     * @return iterable<string, array{string|null, array<string, mixed>, string, 3?: string}>
     */
    public static function provideOneMethod(): iterable
    {
        yield 'header' => ['Bearer ' . self::JWS, [], self::JWS];
        yield 'header, several spaces' => ['Bearer   ' . self::JWS, [], self::JWS];
        yield 'header, scheme in lower case' => ['bearer ' . self::JWS, [], self::JWS];
        yield 'header, scheme in upper case' => ['BEARER ' . self::JWS, [], self::JWS];
        yield 'header, padded token' => ['Bearer abc+/==', [], 'abc+/=='];
        yield 'DPoP header' => ['DPoP ' . self::JWS, [], self::JWS, KeyConfirmation::SCHEME];
        yield 'DPoP header, scheme in lower case' => ['dpop ' . self::JWS, [], self::JWS, KeyConfirmation::SCHEME];
        yield 'body' => [
            null,
            [
                'access_token' => self::JWS,
            ],
            self::JWS,
        ];
        yield 'body next to another scheme' => [
            'Basic Y2xpZW50OnNlY3JldA==',
            [
                'access_token' => self::JWS,
            ],
            self::JWS,
        ];
        yield 'body next to other parameters' => [
            null,
            [
                'other' => 'value',
                'access_token' => self::JWS,
            ],
            self::JWS,
        ];
    }

    /**
     * RFC 6750 §3.1: a request without any bearer token is not an error of the protocol; the resource
     * answers with the bare challenge. A header of another scheme, or an empty parameter (RFC 6749 §3.1,
     * as every endpoint reads them), is no token either.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideNoToken')]
    public function itFindsNoTokenWhenNoneIsSent(?string $header, array $parameters): void
    {
        // When / Then
        static::assertNull($this->parser->parse($header, RequestParameters::of($parameters)));
    }

    /**
     * @return iterable<string, array{string|null, array<string, mixed>}>
     */
    public static function provideNoToken(): iterable
    {
        yield 'nothing' => [null, []];
        yield 'another scheme' => ['Basic Y2xpZW50OnNlY3JldA==', []];
        yield 'a scheme that starts like Bearer' => ['Bearerish ' . self::JWS, []];
        yield 'a scheme that starts like DPoP' => ['DPoPish ' . self::JWS, []];
        yield 'empty header' => ['', []];
        yield 'empty parameter' => [
            null,
            [
                'access_token' => '',
            ],
        ];
        yield 'another parameter' => [
            null,
            [
                'token' => self::JWS,
            ],
        ];
    }

    /**
     * RFC 6750 §2: more than one method is refused; §3.1: a header that names the scheme without a
     * b64token, or a parameter that is not one, is a malformed request: invalid_request, 400, never a
     * redirect.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideMalformed')]
    public function itRefusesAMalformedRequest(?string $header, array $parameters, string $description): void
    {
        // When
        try {
            $this->parser->parse($header, RequestParameters::of($parameters));
            static::fail('The request should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertSame('invalid_request', $exception->error);
            static::assertSame(400, $exception->statusCode);
            static::assertFalse($exception->redirectable);
            static::assertStringContainsString($description, $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{string|null, array<string, mixed>, string}>
     */
    public static function provideMalformed(): iterable
    {
        yield 'both methods' => [
            'Bearer ' . self::JWS,
            [
                'access_token' => self::JWS,
            ],
            'more than one method',
        ];
        yield 'scheme alone' => ['Bearer', [], 'Authorization header'];
        yield 'DPoP scheme alone' => ['DPoP', [], 'Authorization header'];
        yield 'DPoP token with a space' => ['DPoP abc def', [], 'Authorization header'];
        yield 'scheme and spaces' => ['Bearer   ', [], 'Authorization header'];
        yield 'token with a space' => ['Bearer abc def', [], 'Authorization header'];
        yield 'token with a double quote' => ['Bearer "abc"', [], 'Authorization header'];
        yield 'padding before the end' => ['Bearer abc=def', [], 'Authorization header'];
        yield 'tab as separator' => ["Bearer\t" . self::JWS, [], 'Authorization header'];
        yield 'parameter repeated' => [
            null,
            [
                'access_token' => [self::JWS, self::JWS],
            ],
            'access_token parameter',
        ];
        yield 'parameter with a space' => [
            null,
            [
                'access_token' => 'abc def',
            ],
            'access_token parameter',
        ];
        yield 'parameter with a comma' => [
            null,
            [
                'access_token' => 'abc,def',
            ],
            'access_token parameter',
        ];
    }
}
