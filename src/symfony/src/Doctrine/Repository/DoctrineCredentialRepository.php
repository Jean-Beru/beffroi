<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Doctrine\Persistence\ManagerRegistry;
use Heidi\Core\Domain\Credential\Credential;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\CredentialRepositoryInterface;

/**
 * Credentials, one table per kind (architecture §3.4): the password today, passkeys and TOTP when they
 * come, each with its own columns. The credentials of a user are the union of the kinds.
 *
 * @extends DoctrineRepository<PasswordCredential>
 */
final readonly class DoctrineCredentialRepository extends DoctrineRepository implements CredentialRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, PasswordCredential::class);
    }

    public function findByUser(User $user): array
    {
        return $this->repository()
            ->findBy([
                'user' => $user,
            ], [
                'createdAt' => 'ASC',
            ]);
    }

    public function findPasswordCredential(User $user): ?PasswordCredential
    {
        return $this->repository()
            ->findOneBy([
                'user' => $user,
            ]);
    }

    public function save(Credential $credential): void
    {
        $this->store($credential);
    }
}
