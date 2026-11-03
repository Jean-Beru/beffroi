<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use App\Http\RequestContextFactory;
use App\Message\AdvanceKeyLifecycle;
use App\Scheduler\BeffroiSchedule;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeySuccession;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The three timed steps of architecture §3.3, in the order that lets one tick finish a rotation the
 * previous one started: what the console does by hand with "beffroi:keys:rotate", "beffroi:keys:activate"
 * and "beffroi:keys:retire --due".
 *
 * The first one starts a rotation nobody asked for (issue #455), and it comes first for the same reason
 * the other two are in this order: a successor staged here waits its staging window, so the tick that
 * stages it is never the tick that activates it, and a deployment nobody watches does not sign with the
 * same key for ever.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class AdvanceKeyLifecycleHandler
{
    public function __construct(
        private TenantProvider $tenants,
        private KeySuccession $succession,
        private KeyTakeOver $takeOver,
        private KeyRetirement $retirement,
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
        $this->succession->stageSuccessorsDue($tenant, $context);
        $this->takeOver->activateDue($tenant, $context);
        $this->retirement->retireDue($tenant, $context);
    }
}
