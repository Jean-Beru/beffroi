<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;

/**
 * The newest metadata document accepted for each service provider of a tenant, in beffroi_saml_service_provider
 * (beffroi/saml, spec/saml.md S-6, S-8), the document sealed by its type.
 *
 * @extends DoctrineRepository<AcceptedMetadata>
 */
final readonly class DoctrineAcceptedMetadataRepository extends DoctrineRepository implements AcceptedMetadataRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, AcceptedMetadata::class);
    }

    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'entityId' => $entityId,
        ]);
    }

    public function save(AcceptedMetadata $metadata): void
    {
        $this->store($metadata);
    }
}
