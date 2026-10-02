<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Sessions in beffroi_authentication_session (architecture §3.2, §3.4). A DQL parameter that is an
 * identifier names its type: the ORM would infer a string from a Uuid.
 *
 * @extends DoctrineRepository<AuthenticationSession>
 */
final readonly class DoctrineAuthenticationSessionRepository extends DoctrineRepository implements AuthenticationSessionRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, AuthenticationSession::class);
    }

    public function find(Uuid $id): ?AuthenticationSession
    {
        return $this->repository()->findOneBy([
            'id' => $id,
        ]);
    }

    public function findActiveByUser(User $user, DateTimeImmutable $now): array
    {
        /** @var list<AuthenticationSession> */
        return $this->queryBuilder('s')
            ->where('s.user = :user')
            ->andWhere('s.endedAt IS NULL')
            ->andWhere('s.expiresAt > :now')
            ->orderBy('s.establishedAt', 'ASC')
            ->addOrderBy('s.id', 'ASC')
            ->setParameter('user', $user->id, UuidType::NAME)
            ->setParameter('now', $now, Types::DATETIME_IMMUTABLE)
            ->getQuery()
            ->getResult();
    }

    public function save(AuthenticationSession $session): void
    {
        $this->store($session);
    }
}
