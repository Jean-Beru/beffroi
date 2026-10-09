<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Core\Application\Session\SessionProvenanceEnrichment;
use Beffroi\Core\Domain\Event\SessionProvenanceInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Where a session was seen from, written on the lane the events already travel (issue #473): the
 * enrichment of a provenance is asynchronous whatever it reads (architecture §3.5), so nothing of a login
 * waits on a database of addresses, and a login still happens on a deployment that holds none.
 *
 * It handles the interface and not the event, so an event that comes to say a session wrote down where it
 * was seen is covered by saying so on itself (`SessionProvenanceInterface`) and nothing here is edited.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class EnrichTheProvenanceHandler
{
    public function __construct(
        private SessionProvenanceEnrichment $enrichment,
    ) {
    }

    public function __invoke(SessionProvenanceInterface $event): void
    {
        $this->enrichment->enrich($event->sessionId());
    }
}
