<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Client\RedirectUri;

/**
 * A redirect URI as the client presented it (RFC 6749 §3.1.2), byte for byte.
 *
 * @extends StringObjectType<RedirectUri>
 */
final class RedirectUriType extends StringObjectType
{
    public const string NAME = 'beffroi_redirect_uri';

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
