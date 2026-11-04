<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Exchange\PresentedTokenTypes;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;

/**
 * RFC 8693 §3
 */
final readonly class TokenTypes
{
    public static function accessToken(): TokenTypeIdentifier
    {
        return TokenTypeIdentifier::accessToken();
    }

    /**
     * RFC 8693 §3
     */
    public static function invented(): TokenTypeIdentifier
    {
        return new TokenTypeIdentifier('urn:example:params:oauth:token-type:invented');
    }

    /**
     * @param array<string, PresentedToken> $tokens by the value a request presents
     */
    public static function served(array $tokens = []): PresentedTokenTypes
    {
        return new PresentedTokenTypes([new FakePresentedTokenType(self::accessToken(), $tokens)]);
    }
}
