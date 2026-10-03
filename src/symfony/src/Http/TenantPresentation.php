<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * What a page says of the organisation the visitor came for (issue #449): its name, and the logo and the
 * colours it declared. The one object the templates of the interaction plane are given of a tenant, the
 * entity never reaching one: a page shows four values of it and has no business holding the users, the
 * clients and the "acr" vocabulary that come with the row.
 *
 * Flat on purpose. A template reads "tenant.name" and "tenant.logoUri", never "tenant.look.logoUri":
 * where each value is kept is the model's business, and a page that had to walk to it would be a page
 * that breaks when it moves. It is the counterpart, for the tenant, of what a client says of itself on
 * the consent page (ClientPresentation).
 */
final readonly class TenantPresentation
{
    private function __construct(
        public string $name,
        public ?string $logoUri = null,
        public ?string $primaryColor = null,
        public ?string $primaryContentColor = null,
    ) {
    }

    public static function of(Tenant $tenant): self
    {
        return new self(
            $tenant->name,
            $tenant->look->logoUri?->value,
            $tenant->look->primaryColor,
            $tenant->look->primaryContentColor,
        );
    }
}
