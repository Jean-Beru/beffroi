<?php

declare(strict_types=1);

namespace Heidi\Bundle\MessageHandler;

use Heidi\Bundle\Message\SendLogoutToken;
use Heidi\Oidc\Domain\Event\LogoutTokenIssued;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * A token that was minted is a fact the audit reads; carrying it is a piece of work of its own
 * (architecture §5.6). The hop is what keeps the two apart: the send is retried on its own schedule and
 * alone, and a retry never replays what else listens to the end of a session.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class QueueLogoutTokenHandler
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function __invoke(LogoutTokenIssued $event): void
    {
        $this->commandBus->dispatch(SendLogoutToken::of($event));
    }
}
