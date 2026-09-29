<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Doctrine\DBAL\Types\Types;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientMetadataReader;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\Registration\ClientRetention;
use Heidi\Oidc\Port\ClientSourceInterface;
use Heidi\Oidc\Port\ClientStoreInterface;
use Heidi\Oidc\Port\UnusedClientsInterface;

/**
 * The clients this provider registered itself, in heidi_client (RFC 7591 §3.2.1): a source of clients
 * like the configuration of the deployment, and the store the registration endpoint writes to. Nothing
 * downstream learns that a client came from a row rather than from a declaration.
 *
 * A row keeps the metadata as the client registered it, so it is read back by the reader every registration
 * goes through, behind the defaults of RFC 7591 §2 and never those of a deployment: what the client did not
 * ask for is what the specification says it gets. Beside it the row keeps what the registration policy of
 * the tenant wrote on that registration (decision 0017), read in front of it. The secret is the one thing
 * neither carries: the provider assigned it, and the row says by holding one that the registration
 * declares one.
 *
 * @extends DoctrineRepository<ClientRecord>
 */
final readonly class DoctrineClientRepository extends DoctrineRepository implements ClientSourceInterface, ClientStoreInterface, UnusedClientsInterface
{
    public function __construct(
        EntityManagers $managers,
        private ClientMetadataReader $reader,
    ) {
        parent::__construct($managers, ClientRecord::class);
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        $record = $this->record($tenant, $clientId);

        return $record === null ? null : new Client($tenant, $this->registrationOf($record), $record->secret);
    }

    public function registrationsIn(Tenant $tenant): iterable
    {
        foreach ($this->recordsIn($tenant) as $record) {
            yield $this->registrationOf($record);
        }
    }

    public function save(ClientRecord $record): void
    {
        $this->store($record);
    }

    public function findRecord(Tenant $tenant, string $clientId): ?ClientRecord
    {
        return $this->record($tenant, $clientId);
    }

    /**
     * Decision 0009: the clients of that tenant nobody uses any more, in one query on the two dates the
     * retention names rather than a read of the table: a client used before the first, and a client that was
     * never used and drawn before the second. The ones that have waited longest come first, so that a
     * bounded run takes those and the next run takes the rest.
     */
    public function unusedIn(Tenant $tenant, ClientRetention $retention, int $limit): array
    {
        if ($limit < 1) {
            return [];
        }

        /** @var list<ClientRecord> $unused */
        $unused = $this->queryBuilder('c')
            ->andWhere('c.tenant = :tenant')
            ->andWhere('(c.lastUsedAt IS NOT NULL AND c.lastUsedAt < :usedSince) OR (c.lastUsedAt IS NULL AND c.issuedAt < :registeredSince)')
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->setParameter('usedSince', $retention->usedSince, Types::DATETIME_IMMUTABLE)
            ->setParameter('registeredSince', $retention->registeredSince, Types::DATETIME_IMMUTABLE)
            ->addOrderBy('c.lastUsedAt', 'ASC')
            ->addOrderBy('c.issuedAt', 'ASC')
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();

        return $unused;
    }

    /**
     * RFC 7592 §2.3: the row is gone. What names it elsewhere is left where it is, a record whose client
     * no longer resolves being a record nobody finds.
     */
    public function remove(ClientRecord $record): void
    {
        $manager = $this->manager();
        $manager->remove($record);
        $manager->flush();
    }

    private function record(Tenant $tenant, string $clientId): ?ClientRecord
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'clientId' => $clientId,
        ]);
    }

    /**
     * @return list<ClientRecord>
     */
    private function recordsIn(Tenant $tenant): array
    {
        return $this->repository()->findBy([
            'tenant' => $tenant,
        ], [
            'issuedAt' => 'ASC',
        ]);
    }

    /**
     * The metadata read as a declaration is read, strictly and by the same reader: a member this
     * provider does not understand is refused here as it is there, so a row written by a version that
     * read more than this one says so instead of serving a client nobody can account for.
     *
     * What the registration policy of the tenant wrote is read in front of what the client sent
     * (decision 0017), from the row and never from the policy: a policy is read where a registration is
     * written, at the creation of RFC 7591 §3.1 and at the replacement of RFC 7592 §2.2, and never at
     * the authorization request that looks this client up.
     */
    private function registrationOf(ClientRecord $record): ClientRegistration
    {
        return $this->reader->read($record->clientId, $record->asRegistered(), $record->secret !== null);
    }
}
