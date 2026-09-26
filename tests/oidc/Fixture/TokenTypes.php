<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Application\Exchange\PresentedTokenTypes;
use Heidi\Oidc\Domain\Exchange\PresentedToken;
use Heidi\Oidc\Domain\Exchange\TokenTypeIdentifier;

/**
 * The token type identifiers the tests speak of (RFC 8693 §3), and the wirings they read them from. The one
 * type the provider reads today is written here once, so that a test says which type it is about and no test
 * says what the provider is wired with.
 */
final readonly class TokenTypes
{
    public static function accessToken(): TokenTypeIdentifier
    {
        return TokenTypeIdentifier::accessToken();
    }

    /**
     * RFC 8693 §3: a type nobody wrote a line of production code for, named by a URI as every other is.
     */
    public static function invented(): TokenTypeIdentifier
    {
        return new TokenTypeIdentifier('urn:example:params:oauth:token-type:invented');
    }

    /**
     * What the provider is wired to read today: the access token, reading whatever the test put in it.
     *
     * @param array<string, PresentedToken> $tokens by the value a request presents
     */
    public static function served(array $tokens = []): PresentedTokenTypes
    {
        return new PresentedTokenTypes([new FakePresentedTokenType(self::accessToken(), $tokens)]);
    }
}
