<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\PairwiseSaltInterface;

final readonly class FixedPairwiseSalt implements PairwiseSaltInterface
{
    /**
     * @param non-empty-string $salt
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
