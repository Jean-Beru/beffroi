<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\ForgetTheActsPastTheirRetention;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Oidc\Application\Disclosure\DisclosureRetention;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Forgets the acts of the journal past the duration the deployment keeps them for (issue #454), in the
 * shape every timed step of the bundle has: bounded by the store, so a backlog is worked through over
 * several ticks, and silent when there was nothing to forget.
 *
 * **One step for the two tables.** What a client was given of a person is forgotten here too and at the
 * same moment (issue #590), because it is the same duration: an act whose row is gone, or a row whose act
 * is gone, is half an answer. The counts are said apart, each store bounding its own run.
 */
#[AsMessageHandler]
final readonly class ForgetTheActsPastTheirRetentionHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private JournalRetention $retention,
        private DisclosureRetention $disclosures,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(ForgetTheActsPastTheirRetention $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no act to forget, and a tick is not the place to say so
            return;
        }
        $forgotten = $this->retention->enforce($tenant);
        if ($forgotten > 0) {
            $this->logger->info('Forgot {count} act(s) of the journal of the tenant "{tenant}", kept past their retention.', [
                'count' => $forgotten,
                'tenant' => $tenant->slug,
            ]);
        }
        $given = $this->disclosures->enforce($tenant);
        if ($given === 0) {
            return;
        }
        $this->logger->info('Forgot what {count} act(s) of the tenant "{tenant}" had given to a client, kept past the retention of the journal.', [
            'count' => $given,
            'tenant' => $tenant->slug,
        ]);
    }
}
