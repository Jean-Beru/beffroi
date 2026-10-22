<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * The group memberships of a person, in beffroi_group_membership (decision 0002): read for the archive they
 * ask for (issue #453), by the name of the group, so that two files of the same person read alike, and
 * written one row at a time by the sign-in through an upstream provider that replaces the memberships it
 * asserted (issue #782).
 *
 * @extends DoctrineRepository<GroupMembership>
 */
final readonly class DoctrineGroupMembershipRepository extends DoctrineRepository implements GroupMembershipRepositoryInterface, GroupsOfAPersonInterface
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

    public function save(GroupMembership $membership): void
    {
        $this->store($membership);
    }

    public function remove(GroupMembership $membership): void
    {
        $this->discard($membership);
    }
}
