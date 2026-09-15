<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Oidc\Domain\Client\RedirectUri;

/**
 * A redirect URI as the client presented it (RFC 6749 §3.1.2), kept byte for byte because the token endpoint compares it again (RFC 6749 §4.1.3).
 *
 * @extends StringObjectType<RedirectUri>
 */
final class RedirectUriType extends StringObjectType
{
    public const string NAME = 'heidi_redirect_uri';

    protected function encode(object $value): string
    {
        return $value->value;
    }

    protected function decode(string $value): object
    {
        return new RedirectUri($value);
    }

    protected function expects(): string
    {
        return RedirectUri::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
