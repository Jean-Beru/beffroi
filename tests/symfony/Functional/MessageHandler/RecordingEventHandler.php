<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\MessageHandler;

use Beffroi\Core\Domain\Event\DomainEventInterface;
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

    /**
     * Forgets what has been recorded, for a test whose fixture raises events of the class its act is
     * judged on: what it asserts is then what its own act raised.
     */
    public function forget(): void
    {
        $this->events = [];
    }
}
