<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AmbientTenantInterface;

/**
 * The tenant of a unit of work, decided by the test rather than by a request. A deployment has one tenant
 * in its configuration and `TenantProvider` reads it there, so this is what stands in for the two things
 * no configuration of one tenant can show: a second tenant, and a unit of work that has none.
 *
 * Beside the fixtures of the core rather than under one suite, both suites needing it: the unit tests of
 * the encrypter and of the indexes, and the functional tests that stand a second tenant up.
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
