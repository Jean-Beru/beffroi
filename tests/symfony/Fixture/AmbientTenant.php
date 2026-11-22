<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AmbientTenantInterface;

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
