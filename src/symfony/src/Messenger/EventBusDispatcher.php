<?php

declare(strict_types=1);

namespace Heidi\Bundle\Messenger;

use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DispatchAfterCurrentBusStamp;

/**
 * The PSR-14 dispatcher of the core, replaying every event on "event.bus" (architecture §5.6); nothing
 * listens in the process that produced it.
 */
final readonly class EventBusDispatcher implements EventDispatcherInterface
{
    public function __construct(
        private MessageBusInterface $eventBus,
    ) {
    }

    public function dispatch(object $event): object
    {
        $this->eventBus->dispatch(Envelope::wrap($event, [new DispatchAfterCurrentBusStamp()]));

        return $event;
    }
}
