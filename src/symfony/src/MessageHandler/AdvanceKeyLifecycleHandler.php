<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Scheduler\BeffroiSchedule;
use Beffroi\Core\Application\Key\TenantKeyRotator;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The two timed steps of architecture §3.3, in the order that lets one tick finish a rotation the previous
 * one started: what the console does by hand with "beffroi:keys:activate" and "beffroi:keys:retire --due".
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
        $context = $this->contexts->fromSchedule(BeffroiSchedule::NAME);
        $this->rotator->activateDue($tenant, $context);
        $this->rotator->retireDue($tenant, $context);
    }
}
