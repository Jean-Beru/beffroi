<?php

declare(strict_types=1);

namespace Heidi\Bundle\MessageHandler;

use Heidi\Oidc\Application\Client\Registration\ClientUseRecording;
use Heidi\Oidc\Domain\Event\ClientInUseInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The date a stored client carries of its last use (decision 0009), written on the events that say somebody
 * is using it rather than in the requests that serve it: nothing of the protocol waits for this write, and
 * an authorization and a token request are already announcing themselves.
 *
 * It handles the interface and not the two events, so an event that comes to mean the same is covered by
 * saying so on itself (`ClientInUseInterface`) and nothing here is edited.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class RecordClientUseHandler
{
    public function __construct(
        private ClientUseRecording $recording,
    ) {
    }

    public function __invoke(ClientInUseInterface $event): void
    {
        $this->recording->record($event);
    }
}
