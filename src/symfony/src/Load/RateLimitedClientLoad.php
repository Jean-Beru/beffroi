<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Load;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\ClientLoadBudgetInterface;
use function sprintf;

/**
 * The load budget of a client (decision 0014), counted by tenant and by authenticated client: two
 * tenants may register the same identifier, and one bucket for both would make either pay for the
 * other. The identifier of the tenant is a UUID, so nothing a client is named can reach across the
 * separator into another tenant's count.
 */
final readonly class RateLimitedClientLoad implements ClientLoadBudgetInterface
{
    public function __construct(
        private LoadBudget $budget,
    ) {
    }

    public function consume(Tenant $tenant, string $clientId): void
    {
        $this->budget->consume(sprintf('%s|%s', $tenant->id->toRfc4122(), $clientId), $clientId);
    }
}
