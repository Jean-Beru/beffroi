<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use function count;
use DateTimeImmutable;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * The archives a person asked for, in beffroi_personal_archive (issue #453): one row from the moment they
 * ask, the document sealed in it once it is built, and the row gone once it has expired.
 *
 * @extends DoctrineRepository<PersonalArchive>
 */
final readonly class DoctrinePersonalArchiveRepository extends DoctrineRepository implements PersonalArchiveRepositoryInterface
{
    /**
     * How many rows one run of the retention forgets. The bound the journal has, for the same reason: a
     * tick that deleted everything expired in one statement would hold the table of a deployment whose
     * people all asked at once, where the next tick takes what this one left.
     */
    public const int FORGOTTEN_AT_ONCE = 100;

    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, PersonalArchive::class);
    }

    public function find(Tenant $tenant, Uuid $id): ?PersonalArchive
    {
        return $this->repository()->findOneBy([
            'id' => $id,
            'tenant' => $tenant,
        ]);
    }

    public function latestOf(User $user): ?PersonalArchive
    {
        /** @var PersonalArchive|null $archive */
        $archive = $this->queryBuilder('a')
            ->where('a.user = :user')
            ->orderBy('a.askedAt', 'DESC')
            ->addOrderBy('a.id', 'DESC')
            ->setMaxResults(1)
            ->setParameter('user', $user->id, UuidType::NAME)
            ->getQuery()
            ->getOneOrNullResult();

        return $archive;
    }

    public function save(PersonalArchive $archive): void
    {
        $this->store($archive);
    }

    public function forget(PersonalArchive $archive): void
    {
        $this->discard($archive);
    }

    public function forgetExpired(Tenant $tenant, DateTimeImmutable $moment): int
    {
        /** @var list<PersonalArchive> $expired */
        $expired = $this->queryBuilder('a')
            ->where('a.tenant = :tenant')
            ->andWhere('a.expiresAt <= :moment')
            ->orderBy('a.expiresAt', 'ASC')
            ->setMaxResults(self::FORGOTTEN_AT_ONCE)
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->setParameter('moment', $moment)
            ->getQuery()
            ->getResult();
        if ($expired === []) {
            return 0;
        }
        $manager = $this->manager();
        foreach ($expired as $archive) {
            $manager->remove($archive);
        }
        $manager->flush();

        return count($expired);
    }
}
