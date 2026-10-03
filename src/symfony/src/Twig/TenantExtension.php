<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\TenantPresentation;
use Twig\Attribute\AsTwigFunction;

/**
 * What the pages read of the organisation the visitor came for (issue #449): its name, its logo and its
 * colours, in one object (TenantPresentation), and never the entity.
 *
 * A function and not a variable every page is handed, for the reason the languages are one too
 * (LocaleExtension): no page has to pass the layout what the layout shows, and a page that does not ask
 * asks nothing of the database.
 *
 * It answers nothing when there is no tenant to answer with. The page that says the row of the tenant is
 * missing or disagrees with the configuration is a page of this plane as well, and it has to render: a
 * provider that cannot name its tenant still owes a reader the sentence that says so.
 */
final readonly class TenantExtension
{
    public function __construct(
        private TenantProvider $tenants,
    ) {
    }

    #[AsTwigFunction(name: 'beffroi_tenant')]
    public function tenant(): ?TenantPresentation
    {
        try {
            return TenantPresentation::of($this->tenants->provide());
        } catch (TenantNotSynchronizedException) {
            return null;
        }
    }
}
