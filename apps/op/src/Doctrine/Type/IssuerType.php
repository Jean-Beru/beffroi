<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Tenant\Issuer;

/**
 * The issuer identifier of a tenant (OIDC Discovery §3), stored as is.
 *
 * @extends StringObjectType<Issuer>
 */
final class IssuerType extends StringObjectType
{
    public const string NAME = 'beffroi_issuer';

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
