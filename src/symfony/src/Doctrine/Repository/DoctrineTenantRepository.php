<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\TenantRepositoryInterface;

/**
 * The row of the tenant, written by the acts that change what it decided of itself (issue #327). What the
 * configuration says of a tenant is written by TenantSynchronizer, which is another thing: an issuer, a
 * name and an "acr" vocabulary come from the deployment, the floor of its logins from whoever administers
 * it.
 */
final readonly class DoctrineTenantRepository implements TenantRepositoryInterface
{
    public function __construct(
        private EntityManagers $managers,
    ) {
    }

    public function save(Tenant $tenant): void
    {
        $manager = $this->managers->forClass(Tenant::class);
        $manager->persist($tenant);
        $manager->flush();
    }
}
