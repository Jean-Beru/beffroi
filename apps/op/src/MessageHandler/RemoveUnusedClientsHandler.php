<?php

declare(strict_types=1);

namespace App\MessageHandler;

use function count;
use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use App\Http\RequestContextFactory;
use App\Message\RemoveUnusedClients;
use App\Scheduler\BeffroiSchedule;
use Beffroi\Oidc\Application\Client\Registration\UnusedClientRemoval;
use function implode;
use Psr\Log\LoggerInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The timed step of decision 0009, beside the two of the key lifecycle: what the tenant console will do by
 * hand, on a schedule.
 *
 * It says what it did where an operator reads it, and only when it did something: a step that logged a line
 * an hour to say it found nothing is a step nobody reads. Each client removed is announced by its own event
 * as well, which is what an audit trail keeps.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class RemoveUnusedClientsHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private UnusedClientRemoval $removal,
        private RequestContextFactory $contexts,
        private LoggerInterface $logger,
    ) {
    }

    public function __invoke(RemoveUnusedClients $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no client to drop, and a tick is not the place to say so
            return;
        }
        $removed = $this->removal->removeUnused($tenant, $this->contexts->fromSchedule(BeffroiSchedule::NAME));
        if ($removed === []) {
            return;
        }
        $this->logger->info('Removed {count} registered client(s) of the tenant "{tenant}" that nobody used any more: {clients}.', [
            'count' => count($removed),
            'tenant' => $tenant->slug,
            'clients' => implode(', ', $removed),
        ]);
    }
}
