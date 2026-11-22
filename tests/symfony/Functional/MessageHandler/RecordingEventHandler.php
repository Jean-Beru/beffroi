<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use Beffroi\Core\Domain\Event\DomainEventInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

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

    public function forget(): void
    {
        $this->events = [];
    }
}
