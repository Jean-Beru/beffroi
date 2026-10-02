<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function count;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use Beffroi\Oidc\Port\ClientLoadBudgetInterface;
use const PHP_INT_MAX;
use function sprintf;

/**
 * Counts what each client was consumed for and refuses past the number allowed, without a clock: a
 * window that never slides, enough to see that a client is counted where it authenticated and nowhere
 * else, and that a refusal comes out of the endpoint as it was thrown.
 */
final class FakeClientLoadBudget implements ClientLoadBudgetInterface
{
    /**
     * @var list<string> the clients of every request counted, in order
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
