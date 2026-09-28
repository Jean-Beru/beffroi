<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Heidi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Bridge\Configuration\ClientDefinition;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\ClientSourceInterface;
use Heidi\Oidc\Port\ClientStoreInterface;
use Heidi\Oidc\Port\PresentedTokenTypesInterface;
use Heidi\Oidc\Port\ServedAccessTokenShapesInterface;
use Heidi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use Heidi\Oidc\Port\ServedDeliveryModesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;

/**
 * The clients this provider registered itself, in heidi_client (RFC 7591 §3.2.1): a source of clients
 * like the configuration of the deployment, and the store the registration endpoint writes to. Nothing
 * downstream learns that a client came from a row rather than from a declaration.
 *
 * A row keeps the metadata as the client registered it, so it is read back by the reader a declaration
 * goes through and the registration that comes out is the same object. The secret is the one thing the
 * metadata does not carry: the provider assigned it, and the row says by holding one that the
 * registration declares one.
 *
 * @extends DoctrineRepository<ClientRecord>
 */
final readonly class DoctrineClientRepository extends DoctrineRepository implements ClientSourceInterface, ClientStoreInterface
{
    public function __construct(
        EntityManagers $managers,
        private SignatureAlgorithmsInterface $algorithms,
        private ClientAuthenticationMethodsInterface $methods,
        private ServedGrantsInterface $grants,
        private ServedAccessTokenShapesInterface $shapes,
        private CertificateReaderInterface $certificates,
        private KeyEncryptionAlgorithmsInterface $keyEncryption,
        private ContentEncryptionAlgorithmsInterface $contentEncryption,
        private ServedDeliveryModesInterface $deliveryModes,
        private PresentedTokenTypesInterface $tokenTypes,
        private ServedAuthorizationDetailTypesInterface $authorizationDetailTypes,
    ) {
        parent::__construct($managers, ClientRecord::class);
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        $record = $this->record($tenant, $clientId);

        return $record === null ? null : $this->definitionOf($record)->toClient($tenant, $record->secret);
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

    private function registrationOf(ClientRecord $record): ClientRegistration
    {
        return $this->definitionOf($record)->registration;
    }

    /**
     * The metadata read as a declaration is read, strictly and by the same reader: a member this
     * provider does not understand is refused here as it is there, so a row written by a version that
     * read more than this one says so instead of serving a client nobody can account for.
     */
    private function definitionOf(ClientRecord $record): ClientDefinition
    {
        return ClientDefinition::fromArray(
            $record->clientId,
            $record->metadata,
            $this->algorithms,
            $this->methods,
            $this->grants,
            $this->shapes,
            $this->certificates,
            $this->keyEncryption,
            $this->contentEncryption,
            $this->deliveryModes,
            $this->tokenTypes,
            $this->authorizationDetailTypes,
            $record->secret !== null,
        );
    }
}
