<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantSynchronizer;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The first step of a provisioning (architecture §5.3, §5.5): the row of the configured tenant.
 */
#[AsCommand(
    name: 'heidi:tenant:synchronize',
    description: 'Write the row of the tenant of the configuration: created, renamed, or left alone.',
)]
final readonly class TenantSynchronizeCommand
{
    public function __construct(
        private TenantSynchronizer $synchronizer,
    ) {
    }

    public function __invoke(SymfonyStyle $io): int
    {
        try {
            $tenant = $this->synchronizer->synchronize();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $io->definitionList(
            [
                'Slug' => $tenant->slug,
            ],
            [
                'Issuer' => (string) $tenant->issuer,
            ],
            [
                'Name' => $tenant->name,
            ],
            [
                'Identifier' => $tenant->id->toRfc4122(),
            ],
        );
        $io->success(sprintf('The tenant "%s" is synchronised with the configuration.', $tenant->slug));

        return Command::SUCCESS;
    }
}
