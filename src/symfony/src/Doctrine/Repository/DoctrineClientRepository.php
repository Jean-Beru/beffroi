<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientMetadataReader;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Heidi\Oidc\Port\ClientSourceInterface;
use Heidi\Oidc\Port\ClientStoreInterface;

/**
 * The clients this provider registered itself, in heidi_client (RFC 7591 §3.2.1): a source of clients
 * like the configuration of the deployment, and the store the registration endpoint writes to. Nothing
 * downstream learns that a client came from a row rather than from a declaration.
 *
 * A row keeps the metadata as the client registered it, so it is read back by the reader every registration
 * goes through, behind the defaults of RFC 7591 §2 and never those of a deployment: what the client did not
 * ask for is what the specification says it gets. The secret is the one thing the metadata does not carry:
 * the provider assigned it, and the row says by holding one that the registration declares one.
 *
 * @extends DoctrineRepository<ClientRecord>
 */
final readonly class DoctrineClientRepository extends DoctrineRepository implements ClientSourceInterface, ClientStoreInterface
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
     */
    private function registrationOf(ClientRecord $record): ClientRegistration
    {
        return $this->reader->read(
            $record->clientId,
            new ClientMetadata([new RegisteredMembers($record->metadata), new SpecifiedDefaults()]),
            $record->secret !== null,
        );
    }
}
