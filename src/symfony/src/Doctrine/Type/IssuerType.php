<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Core\Domain\Tenant\Issuer;

/**
 * The issuer identifier of a tenant (OIDC Discovery §3), stored as the string clients compare byte for byte.
 *
 * @extends StringObjectType<Issuer>
 */
final class IssuerType extends StringObjectType
{
    public const string NAME = 'heidi_issuer';

    protected function encode(object $value): string
    {
        return $value->value;
    }

    protected function decode(string $value): object
    {
        return new Issuer($value);
    }

    protected function expects(): string
    {
        return Issuer::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
