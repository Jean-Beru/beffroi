<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use function array_values;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * Consents in beffroi_consent (architecture §4.3); the one in force is the active one granted last.
 *
 * @extends DoctrineRepository<Consent>
 */
final readonly class DoctrineConsentRepository extends DoctrineRepository implements ConsentRepositoryInterface, ActiveConsentsInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, Consent::class);
    }

    public function findActive(User $user, Client $client): ?Consent
    {
        /** @var Consent|null $consent */
        $consent = $this->queryBuilder('c')
            ->where('c.user = :user')
            ->andWhere('c.clientId = :clientId')
            ->andWhere('c.revokedAt IS NULL')
            ->orderBy('c.grantedAt', 'DESC')
            ->addOrderBy('c.id', 'DESC')
            ->setParameter('user', $user->id, UuidType::NAME)
            ->setParameter('clientId', $client->registration->clientId)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();

        return $consent !== null && ClientResolver::isResolved($consent) ? $consent : null;
    }

    /**
     * One line per client, the one findActive() would answer for it: a consent superseded by another is
     * revoked at that instant, and a row left active beside a newer one is not a second agreement.
     *
     * @return list<Consent>
     */
    public function activeOf(User $user): array
    {
        /** @var list<Consent> $consents */
        $consents = $this->queryBuilder('c')
            ->where('c.user = :user')
            ->andWhere('c.revokedAt IS NULL')
            ->orderBy('c.grantedAt', 'DESC')
            ->addOrderBy('c.id', 'DESC')
            ->setParameter('user', $user->id, UuidType::NAME)
            ->getQuery()
            ->getResult();
        $found = [];
        foreach ($consents as $consent) {
            if (ClientResolver::isResolved($consent)) {
                $found[$consent->clientId] ??= $consent;
            }
        }

        return array_values($found);
    }

    public function save(Consent $consent): void
    {
        $this->store($consent);
    }
}
