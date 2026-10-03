<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use function is_string;

/**
 * What a tenant shows of itself on the pages of its provider (issue #449) as a JSON document: the URL of
 * its logo and its two colours, each absent from it when the tenant declared none, so that what a tenant
 * declared is what the column holds and not three nulls.
 *
 * A tenant that declared nothing is therefore an empty document, which PHP writes as "[]" where the
 * default of the column is "{}" (both are read back as the same look, and nothing queries a value of this
 * column). Forcing one shape belongs to neither place: the base type serves documents and lists alike,
 * an empty list of backup codes being an empty JSON array for good reason.
 *
 * The value object reads what it is given back, which is what refuses a row somebody edited by hand: a
 * colour that is not hexadecimal and a logo that is not an absolute HTTPS URL are refused here as they
 * are refused at the configuration.
 *
 * @extends JsonObjectType<TenantLook>
 */
final class TenantLookType extends JsonObjectType
{
    public const string NAME = 'beffroi_tenant_look';

    protected function encode(object $value): array
    {
        $document = [];
        if ($value->logoUri !== null) {
            $document['logo_uri'] = $value->logoUri->value;
        }
        if ($value->primaryColor !== null) {
            $document['primary_color'] = $value->primaryColor;
        }
        if ($value->primaryContentColor !== null) {
            $document['primary_content_color'] = $value->primaryContentColor;
        }

        return $document;
    }

    protected function decode(array $data): object
    {
        $logoUri = $data['logo_uri'] ?? null;
        $primaryColor = $data['primary_color'] ?? null;
        $primaryContentColor = $data['primary_content_color'] ?? null;
        if (
            $logoUri !== null && ! is_string($logoUri)
            || $primaryColor !== null && ! is_string($primaryColor)
            || $primaryContentColor !== null && ! is_string($primaryContentColor)
        ) {
            throw ValueNotConvertible::new(
                $data,
                self::NAME,
                'The look of a tenant holds the URL of a logo and two colours, each of them a string when it is there at all.',
            );
        }

        return new TenantLook(
            $logoUri === null ? null : new LogoUri($logoUri),
            $primaryColor,
            $primaryContentColor,
        );
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
