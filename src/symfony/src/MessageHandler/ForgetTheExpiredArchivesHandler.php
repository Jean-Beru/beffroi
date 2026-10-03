<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\ForgetTheExpiredArchives;
use Beffroi\Core\Application\Archive\ArchiveRetention;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Forgets the archives that have expired (issue #453), in the shape every timed step of the bundle has:
 * bounded by the store, so a backlog is worked through over several ticks, and silent when there was
 * nothing to forget.
 *
 * It is said out loud when it did something, where the retention of the journal says the same of an act:
 * a file holding everything this provider knows of a person going away is worth a line.
 */
#[AsMessageHandler]
final readonly class ForgetTheExpiredArchivesHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private ArchiveRetention $retention,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(ForgetTheExpiredArchives $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning nobody has asked for an archive, and a tick is not the place
            // to say so
            return;
        }
        $forgotten = $this->retention->enforce($tenant);
        if ($forgotten === 0) {
            return;
        }
        $this->logger->info('Forgot {count} expired archive(s) of the tenant "{tenant}".', [
            'count' => $forgotten,
            'tenant' => $tenant->slug,
        ]);
    }
}
