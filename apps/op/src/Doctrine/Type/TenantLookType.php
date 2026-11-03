<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Tenant\TenantLook;

/**
 * What a tenant shows of itself on the pages of its provider (issue #449) as a JSON column. What the
 * document holds, and what it leaves out when the tenant declared nothing, is the look's own
 * (`TenantLook::toDocument()`).
 *
 * @extends JsonObjectType<TenantLook>
 */
final class TenantLookType extends JsonObjectType
{
    public const string NAME = 'beffroi_tenant_look';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return TenantLook::fromDocument($data);
    }

    protected function expects(): string
    {
        return TenantLook::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
