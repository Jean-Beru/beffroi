<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\GroupRepositoryInterface;

/**
 * The groups of a tenant, in beffroi_group (decision 0002), found by tenant and name as the unique constraint
 * of the table holds them. The name is in clear, a group naming an organisational unit and not a person.
 *
 * @extends DoctrineRepository<Group>
 */
final readonly class DoctrineGroupRepository extends DoctrineRepository implements GroupRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, Group::class);
    }

    public function findByName(Tenant $tenant, string $name): ?Group
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'name' => $name,
        ]);
    }

    public function save(Group $group): void
    {
        $this->store($group);
    }
}
