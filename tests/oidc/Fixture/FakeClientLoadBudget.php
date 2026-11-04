<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function count;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use Beffroi\Oidc\Port\ClientLoadBudgetInterface;
use const PHP_INT_MAX;
use function sprintf;

final class FakeClientLoadBudget implements ClientLoadBudgetInterface
{
    /**
     * @var list<string>
     */
    public private(set) array $consumed = [];

    public function __construct(
        private readonly int $allowed = PHP_INT_MAX,
    ) {
    }

    public function consume(Tenant $tenant, string $clientId): void
    {
        $this->consumed[] = sprintf('%s|%s', $tenant->slug, $clientId);
        if (count($this->consumed) > $this->allowed) {
            throw new LoadBudgetSpentException('client', 42, $clientId);
        }
    }
}
