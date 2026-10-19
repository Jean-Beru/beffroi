<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;

/**
 * The accepted documents in the memory of the test, counting what was saved, so that a test can say nothing was
 * written, and forgetting one when told.
 */
final class InMemoryAcceptedMetadata implements AcceptedMetadataRepositoryInterface, CanForgetAcceptedMetadataInterface
{
    public private(set) int $saves = 0;

    /**
     * @var array<string, AcceptedMetadata>
     */
    private array $rows = [];

    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata
    {
        return $this->rows[self::key($tenant, $entityId)] ?? null;
    }

    public function save(AcceptedMetadata $metadata): void
    {
        ++$this->saves;
        $this->rows[self::key($metadata->tenant, $metadata->entityId)] = $metadata;
    }

    public function forget(AcceptedMetadata $metadata): void
    {
        unset($this->rows[self::key($metadata->tenant, $metadata->entityId)]);
    }

    private static function key(Tenant $tenant, string $entityId): string
    {
        return $tenant->id->toRfc4122() . ' ' . $entityId;
    }
}
