<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Doctrine\PersonalData;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Port\AmbientTenantInterface;

/**
 * The tenant of a unit of work, decided by the test rather than by a request. A deployment has one tenant
 * in its configuration and `TenantProvider` reads it there, so this is what stands in for the two things
 * no configuration of one tenant can show: a second tenant, and a unit of work that has none.
 */
final class AmbientTenant implements AmbientTenantInterface
{
    public function __construct(
        public ?Tenant $tenant,
    ) {
    }

    public function provide(): Tenant
    {
        return $this->tenant ?? throw new RuntimeException('No tenant is ambient.');
    }
}
