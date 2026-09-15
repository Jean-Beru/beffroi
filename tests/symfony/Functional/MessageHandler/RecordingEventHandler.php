<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\MessageHandler;

use Heidi\Core\Domain\Event\DomainEventInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Records what reaches the event bus, for the tests that check the events of the core get there.
 */
#[AsMessageHandler(bus: 'event.bus')]
final class RecordingEventHandler
{
    /**
     * @var list<DomainEventInterface>
     */
    public private(set) array $events = [];

    public function __invoke(DomainEventInterface $event): void
    {
        $this->events[] = $event;
    }
}
