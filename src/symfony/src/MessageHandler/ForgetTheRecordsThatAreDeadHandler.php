<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\ForgetTheRecordsThatAreDead;
use Beffroi\Core\Application\Record\DeadRecordRemoval;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Drops the rows that can no longer do anything (issue #177), in the shape every timed step of the bundle
 * has: bounded by the stores, so a backlog is worked through over several ticks, and silent when there was
 * nothing to drop.
 */
#[AsMessageHandler]
final readonly class ForgetTheRecordsThatAreDeadHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private DeadRecordRemoval $removal,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(ForgetTheRecordsThatAreDead $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no row to drop, and a tick is not the place to say so
            return;
        }
        $forgotten = $this->removal->removeDead($tenant);
        if ($forgotten === 0) {
            return;
        }
        $this->logger->info('Dropped {count} row(s) of the tenant "{tenant}" that could no longer do anything.', [
            'count' => $forgotten,
            'tenant' => $tenant->slug,
        ]);
    }
}
