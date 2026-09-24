<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine;

use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Domain\Tenant\Tenant;

/**
 * Writes the row of the configured tenant: created, renamed, its "acr" policy replaced, or left alone. A
 * changed issuer is refused, every token issued so far names it.
 */
final readonly class TenantSynchronizer
{
    public function __construct(
        private TenantFactory $factory,
        private EntityManagers $managers,
    ) {
    }

    /**
     * @throws TenantNotSynchronizedException when the configuration changed the issuer of a stored tenant
     */
    public function synchronize(): Tenant
    {
        $configured = $this->factory->create();
        $manager = $this->managers->forClass(Tenant::class);
        $tenant = $manager->find(Tenant::class, $configured->id);
        if ($tenant === null) {
            $manager->persist($configured);
            $manager->flush();

            return $configured;
        }
        if (! $tenant->issuer->equals($configured->issuer)) {
            throw TenantNotSynchronizedException::issuerChangeRefused($configured->slug, (string) $tenant->issuer, (string) $configured->issuer);
        }
        if ($tenant->name !== $configured->name) {
            $tenant->rename($configured->name);
        }
        if (! $tenant->authenticationContextPolicy->equals($configured->authenticationContextPolicy)) {
            $tenant->adoptAuthenticationContextPolicy($configured->authenticationContextPolicy);
        }
        $manager->flush();

        return $tenant;
    }
}
