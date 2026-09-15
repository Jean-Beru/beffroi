<?php

declare(strict_types=1);

namespace Heidi\Bundle\Messenger;

use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DispatchAfterCurrentBusStamp;

/**
 * The PSR-14 dispatcher the core and the module announce their events to (architecture §5.6): every event
 * is replayed on "event.bus", where the routing of the application sends it to the low-priority transport
 * and the handlers of the bundle record, enrich and react to it, asynchronously. Announced from inside a
 * handler, the event leaves once that handler has finished, after its transaction has committed; announced
 * from a controller, it leaves at once. Nothing listens in the process that produced it.
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
