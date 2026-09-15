<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The keys the JWK Set publishes (architecture §3.3): the active one, and those retiring since a rotation.
 * A retired key is out of the set and out of this list.
 */
#[AsCommand(
    name: 'heidi:keys:list',
    description: 'List the published signing keys of the tenant: the active one and the retiring ones.',
)]
final readonly class KeysListCommand
{
    public function __construct(
        private TenantProvider $tenants,
        private SigningKeyRepositoryInterface $keys,
    ) {
    }

    public function __invoke(SymfonyStyle $io): int
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $keys = $this->keys->findPublished($tenant);
        if ($keys === []) {
            $io->warning(sprintf('The tenant "%s" has no published key: nothing can be signed. Run "heidi:keys:generate".', $tenant->slug));

            return Command::SUCCESS;
        }

        $rows = [];
        foreach ($keys as $key) {
            $rows[] = [
                $key->kid,
                $key->algorithm->value,
                $key->status->value,
                $key->createdAt->format(DateTimeInterface::RFC3339),
                $key->retiringAt?->format(DateTimeInterface::RFC3339) ?? '',
            ];
        }
        $io->table(['Key identifier', 'Algorithm', 'Status', 'Created at', 'Retiring since'], $rows);

        return Command::SUCCESS;
    }
}
