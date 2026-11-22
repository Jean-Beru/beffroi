<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function array_values;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Port\LogoutChainRepositoryInterface;

/**
 * spec/saml.md S-32
 */
final class InMemoryLogoutChains implements LogoutChainRepositoryInterface
{
    /**
     * @var array<string, LogoutChain>
     */
    private array $chains = [];

    public function save(LogoutChain $chain): void
    {
        $this->chains[$chain->reference] = $chain;
    }

    public function ofReference(Tenant $tenant, string $reference): ?LogoutChain
    {
        $chain = $this->chains[LogoutChain::digestOf($reference)] ?? null;

        return $chain !== null && $chain->tenant->equals($tenant) ? $chain : null;
    }

    public function awaiting(Tenant $tenant, string $requestId): ?LogoutChain
    {
        foreach ($this->chains as $chain) {
            if ($chain->awaitingRequest === $requestId && $chain->tenant->equals($tenant)) {
                return $chain;
            }
        }

        return null;
    }

    public function take(LogoutChain $chain): bool
    {
        $held = $this->chains[$chain->reference] ?? null;
        if ($held === null || $held->awaitingRequest !== $chain->awaitingRequest) {
            return false;
        }
        unset($this->chains[$chain->reference]);

        return true;
    }

    /**
     * @return list<LogoutChain> in the order they were written
     */
    public function all(): array
    {
        return array_values($this->chains);
    }
}
