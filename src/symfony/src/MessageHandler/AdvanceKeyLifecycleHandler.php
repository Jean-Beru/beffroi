<?php

declare(strict_types=1);

namespace Heidi\Bundle\MessageHandler;

use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Message\AdvanceKeyLifecycle;
use Heidi\Bundle\Scheduler\HeidiSchedule;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The two timed steps of architecture §3.3, in the order that lets one tick finish a rotation the previous
 * one started: what the console does by hand with "heidi:keys:activate" and "heidi:keys:retire --due".
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class AdvanceKeyLifecycleHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private TenantKeyRotator $rotator,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(AdvanceKeyLifecycle $message): void
    {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException) {
            // before the first provisioning there is no key to move, and a tick is not the place to say so
            return;
        }
        $context = $this->contexts->fromSchedule(HeidiSchedule::NAME);
        $this->rotator->activateDue($tenant, $context);
        $this->rotator->retireDue($tenant, $context);
    }
}
