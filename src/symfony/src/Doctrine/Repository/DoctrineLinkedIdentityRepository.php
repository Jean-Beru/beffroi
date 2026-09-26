<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Identity\LinkedIdentity;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\LinkedIdentityRepositoryInterface;

/**
 * The identities of a user at an upstream provider, in heidi_linked_identity (architecture §3.1); a lookup is
 * scoped by the tenant and exact, as the unique constraint of the table is.
 *
 * @extends DoctrineRepository<LinkedIdentity>
 */
final readonly class DoctrineLinkedIdentityRepository extends DoctrineRepository implements LinkedIdentityRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, LinkedIdentity::class);
    }

    public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'provider' => $provider,
            'subject' => $subject,
        ]);
    }

    public function save(LinkedIdentity $identity): void
    {
        $this->store($identity);
    }
}
