<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\ImageSource;
use Beffroi\Bundle\Http\TenantPresentation;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\HttpFoundation\RequestStack;
use Twig\Attribute\AsTwigFunction;

/**
 * What the pages read of the organisation the visitor came for (issue #449): its name, its logo and its
 * colours, in one object (TenantPresentation), and never the entity.
 *
 * A function and not a variable every page is handed, for the reason the languages are one too
 * (LocaleExtension): no page has to pass the layout what the layout shows, and a page that does not ask
 * asks nothing of the database.
 *
 * A page that reads the tenant may show its logo, and a deployment may serve that logo from another host
 * than its issuer, a CDN or the site of its organisation (issue #926). So reading it names the origin of
 * that logo for the page being answered, and the "img-src" of the policy that page carries is completed
 * with it (ImageSource): whichever page shows the logo, through whichever layout, its policy names where
 * the logo is served from, and no deployment names that origin by hand. A page that reads nothing of the
 * tenant names nothing.
 *
 * It answers nothing when there is no tenant to answer with. The page that says the row of the tenant is
 * missing or disagrees with the configuration is a page of this plane as well, and it has to render: a
 * provider that cannot name its tenant still owes a reader the sentence that says so.
 */
final readonly class TenantExtension
{
    public function __construct(
        private TenantProvider $tenants,
        private ImageSource $images,
        private RequestStack $requests,
    ) {
    }

    #[AsTwigFunction(name: 'beffroi_tenant')]
    public function tenant(): ?TenantPresentation
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            return null;
        }
        $this->mayShowTheLogoOf($tenant);

        return TenantPresentation::of($tenant);
    }

    /**
     * Named on the main request, which is the one whose answer leaves with a policy: a page rendered by a
     * sub-request, the error page of an exception the kernel caught among them, leaves as its answer. A
     * template rendered outside any request, by a worker, answers nobody and names nothing.
     */
    private function mayShowTheLogoOf(Tenant $tenant): void
    {
        $logo = $tenant->look->logoUri;
        $request = $this->requests->getMainRequest();
        if ($logo === null || $request === null) {
            return;
        }
        $this->images->mayLoadFrom($request, [$logo->origin]);
    }
}
