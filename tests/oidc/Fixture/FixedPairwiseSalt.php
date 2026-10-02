<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\PairwiseSaltInterface;

/**
 * A salt a test can write out, so that the identifier a test computes by hand is the identifier the
 * provider computes. Never leaves the test suite.
 */
final readonly class FixedPairwiseSalt implements PairwiseSaltInterface
{
    /**
     * @param non-empty-string $salt the same salt for every tenant, unless the test asks for one per tenant
     */
    public function __construct(
        private string $salt = 'a-salt-the-deployment-drew-once!',
        private bool $perTenant = false,
    ) {
    }

    public function saltOf(Tenant $tenant): string
    {
        return $this->perTenant ? $this->salt . '|' . $tenant->slug : $this->salt;
    }
}
