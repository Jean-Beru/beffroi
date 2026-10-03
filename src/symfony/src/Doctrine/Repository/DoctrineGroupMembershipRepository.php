<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * The group memberships of a person, in beffroi_group_membership (decision 0002): read for the archive they
 * ask for (issue #453), by the name of the group, so that two files of the same person read alike.
 *
 * @extends DoctrineRepository<GroupMembership>
 */
final readonly class DoctrineGroupMembershipRepository extends DoctrineRepository implements GroupsOfAPersonInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, GroupMembership::class);
    }

    public function of(User $user): array
    {
        /** @var list<GroupMembership> $memberships */
        $memberships = $this->queryBuilder('m')
            ->join('m.group', 'g')
            ->where('m.user = :user')
            ->orderBy('g.name', 'ASC')
            ->setParameter('user', $user->id, UuidType::NAME)
            ->getQuery()
            ->getResult();

        return $memberships;
    }
}
