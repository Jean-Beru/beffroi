<?php

declare(strict_types=1);

namespace App\Profiler;

use function array_slice;
use function explode;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use function implode;
use Psr\EventDispatcher\EventDispatcherInterface;
use const DATE_ATOM;

/**
 * The events the core announced while the request was served (architecture §3.5), on their way to the
 * bus. What the panel shows of one is its name and when it happened: an event carries the tenant, the
 * user and the context of the request, and none of that belongs on a page a developer leaves open.
 */
final readonly class ProfilingEventDispatcher implements EventDispatcherInterface
{
    public function __construct(
        private EventDispatcherInterface $events,
        private OpProfile $profile,
    ) {
    }

    public function dispatch(object $event): object
    {
        $this->profile->record(new Observation('Events', 'Event', [
            'name' => self::nameOf($event),
            'at' => $event instanceof DomainEventInterface ? $event->occurredAt->format(DATE_ATOM) : 'during this request',
        ]));

        return $this->events->dispatch($event);
    }

    /**
     * The class without its namespace, which is what the core calls the event; two events of the same
     * name in two namespaces would be two rows saying the same thing, and there are none.
     */
    private static function nameOf(object $event): string
    {
        $parts = explode('\\', $event::class);

        return implode('', array_slice($parts, -1));
    }
}
