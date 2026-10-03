<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\ForgetTheChangesPastTheirRetention;
use Beffroi\Core\Application\Identity\ClaimHistoryRetention;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Forgets what a record used to say past the duration the deployment keeps it for (issue #482), in the
 * shape every timed step of the bundle has: bounded by the store, so a backlog is worked through over
 * several ticks, and silent when there was nothing to forget.
 */
#[AsMessageHandler]
final readonly class ForgetTheChangesPastTheirRetentionHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private ClaimHistoryRetention $retention,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(ForgetTheChangesPastTheirRetention $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning no record has changed, and a tick is not the place to say so
            return;
        }
        $forgotten = $this->retention->enforce($tenant);
        if ($forgotten === 0) {
            return;
        }
        $this->logger->info('Forgot {count} change(s) of a record of the tenant "{tenant}", kept past their retention.', [
            'count' => $forgotten,
            'tenant' => $tenant->slug,
        ]);
    }
}
