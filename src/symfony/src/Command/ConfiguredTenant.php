<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The tenant every command of the bundle works on, and the one thing to say when its row is not there
 * or no longer says what the configuration says. A command reads it and stops; what to do about it is
 * the same answer wherever it is asked, so it is written here alone.
 */
final readonly class ConfiguredTenant
{
    public function __construct(
        private TenantProvider $tenants,
    ) {
    }

    /**
     * @return Tenant|null null when the command was told why it cannot go on, and should fail
     */
    public function orTold(SymfonyStyle $io): ?Tenant
    {
        try {
            return $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "beffroi:tenant:synchronize" first.']);

            return null;
        }
    }
}
