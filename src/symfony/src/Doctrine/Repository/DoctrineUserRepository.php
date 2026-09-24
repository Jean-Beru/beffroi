<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\UserRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Users in heidi_user (architecture §3.4); a lookup is scoped by the tenant and exact.
 *
 * @extends DoctrineRepository<User>
 */
final readonly class DoctrineUserRepository extends DoctrineRepository implements UserRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, User::class);
    }

    public function find(Uuid $id): ?User
    {
        return $this->repository()->findOneBy([
            'id' => $id,
        ]);
    }

    public function findBySubject(Tenant $tenant, Subject $subject): ?User
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'subject' => $subject,
        ]);
    }

    public function findByUsername(Tenant $tenant, string $username): ?User
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'username' => $username,
        ]);
    }

    public function save(User $user): void
    {
        $this->store($user);
    }
}
