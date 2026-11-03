<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\ClientInventory;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use function sprintf;
use Symfony\Component\Console\Style\SymfonyStyle;
use function trim;

/**
 * The client a command names on its command line, of the tenant it works on. The identifier is read as
 * the shell handed it over, without the spaces a copied value carries, and an identifier no client of
 * the tenant carries is said the same way by every command that takes one (`NamedUser`).
 */
final readonly class NamedClient
{
    public function __construct(
        private ClientInventory $clients,
    ) {
    }

    /**
     * @return InventoriedClient|null null when the command was told there is no such client, and should
     *                                fail
     */
    public function orTold(SymfonyStyle $io, Tenant $tenant, string $clientId): ?InventoriedClient
    {
        $named = trim($clientId);
        $client = $this->clients->find($tenant, $named);
        if ($client === null) {
            $io->error(sprintf('There is no client "%s" in the tenant "%s".', $named, $tenant->slug));

            return null;
        }

        return $client;
    }
}
