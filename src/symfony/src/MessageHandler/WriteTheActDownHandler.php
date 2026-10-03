<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Core\Application\Journal\ActRecording;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Oidc\Domain\Event\ConcernsAClientInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Every act of the provider written down (issue #454), on the lane the events already travel: the journal
 * is never on the path of a request, and an act that cannot be written down does not undo what was done.
 *
 * It handles the interface and not the events, so an event added to either package is journalled by
 * existing at all, and the name it is written under is the one it gives itself. What it says of the person
 * and of the client is what the event declares it says, by the two interfaces of its capability; an event
 * that declares neither leaves those columns empty, which is the honest answer for a key that rotated or a
 * budget that was spent.
 *
 * This is the one place where both packages are read at once, which is why the mapping is here and not in
 * a use case: the core cannot see what the protocol calls a client.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class WriteTheActDownHandler
{
    public function __construct(
        private ActRecording $recording,
    ) {
    }

    public function __invoke(DomainEventInterface $event): void
    {
        $this->recording->record(
            $event->tenant,
            $event->name(),
            $event->occurredAt,
            $event->context,
            $event instanceof ConcernsAPersonInterface ? $event->subject() : null,
            $event instanceof ConcernsAClientInterface ? $event->clientId : null,
        );
    }
}
