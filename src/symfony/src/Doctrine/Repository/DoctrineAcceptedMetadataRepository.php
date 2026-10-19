<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;
use Doctrine\ORM\Mapping\ClassMetadata;
use LogicException;
use function sprintf;

/**
 * The newest metadata document accepted for each service provider of a tenant, in beffroi_saml_service_provider
 * (beffroi/saml, spec/saml.md S-6, S-8), the document sealed by its type, and the row an operator forgets (section
 * 6.2).
 *
 * @extends DoctrineRepository<AcceptedMetadata>
 */
final readonly class DoctrineAcceptedMetadataRepository extends DoctrineRepository implements
    AcceptedMetadataRepositoryInterface,
    CanForgetAcceptedMetadataInterface
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

    /**
     * One INSERT through the connection and not the unit of work, as a pairwise subject is recorded: the console and
     * the hourly step registering the same service provider at the same minute both find no row and race into the
     * unique index of the tenant and the entity ID, where one of them writes nothing and neither fails. A flush could
     * not promise that: the violation would close the unit of work for every service provider read after it. The
     * columns and their types are read from the mapping, the document sealed by the type it maps to (S-8).
     */
    public function register(AcceptedMetadata $metadata): bool
    {
        $manager = $this->manager();
        $class = $manager->getClassMetadata(AcceptedMetadata::class);
        $tenant = $class->getSingleAssociationJoinColumnName('tenant');
        $entityId = $class->getColumnName('entityId');

        return $manager->getConnection()->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (:id, :tenant, :entityId, :document, :validUntil, :acceptedAt) ON CONFLICT (%s, %s) DO NOTHING',
                $class->getTableName(),
                $class->getColumnName('id'),
                $tenant,
                $entityId,
                $class->getColumnName('document'),
                $class->getColumnName('validUntil'),
                $class->getColumnName('acceptedAt'),
                $tenant,
                $entityId,
            ),
            [
                'id' => $metadata->id,
                'tenant' => $metadata->tenant->id,
                'entityId' => $metadata->entityId,
                'document' => $metadata->document,
                'validUntil' => $metadata->validUntil,
                'acceptedAt' => $metadata->acceptedAt,
            ],
            [
                'id' => self::type($class, 'id'),
                'tenant' => 'uuid',
                'entityId' => self::type($class, 'entityId'),
                'document' => self::type($class, 'document'),
                'validUntil' => self::type($class, 'validUntil'),
                'acceptedAt' => self::type($class, 'acceptedAt'),
            ],
        ) === 1;
    }

    public function save(AcceptedMetadata $metadata): void
    {
        $this->store($metadata);
    }

    public function forget(AcceptedMetadata $metadata): void
    {
        $this->discard($metadata);
    }

    /**
     * @param ClassMetadata<AcceptedMetadata> $class
     */
    private static function type(ClassMetadata $class, string $field): string
    {
        return $class->getTypeOfField($field) ?? throw new LogicException(sprintf('The mapping of %s gives "%s" no type.', AcceptedMetadata::class, $field));
    }
}
