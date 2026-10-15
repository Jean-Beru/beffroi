<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;

/**
 * The accepted documents in the memory of the test, counting what was saved, so that a test can say nothing was
 * written.
 */
final class InMemoryAcceptedMetadata implements AcceptedMetadataRepositoryInterface
{
    public private(set) int $saves = 0;

    /**
     * @var array<string, AcceptedMetadata>
     */
    private array $rows = [];

    public function find(Tenant $tenant, string $entityId): ?AcceptedMetadata
    {
        return $this->rows[$tenant->id->toRfc4122() . ' ' . $entityId] ?? null;
    }

    public function save(AcceptedMetadata $metadata): void
    {
        ++$this->saves;
        $this->rows[$metadata->tenant->id->toRfc4122() . ' ' . $metadata->entityId] = $metadata;
    }
}
