<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * Consents in heidi_consent (architecture §4.3); the one in force is the active one granted last.
 *
 * @extends DoctrineRepository<Consent>
 */
final readonly class DoctrineConsentRepository extends DoctrineRepository implements ConsentRepositoryInterface
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

    public function save(Consent $consent): void
    {
        $this->store($consent);
    }
}
