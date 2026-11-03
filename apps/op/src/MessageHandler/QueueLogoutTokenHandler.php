<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\EndSession\LogoutChannelInterface;
use App\Message\SendLogoutToken;
use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * A token that was minted is a fact the audit reads; carrying it is a piece of work of its own
 * (architecture §5.6). The hop is what keeps the two apart: the send is retried on its own schedule and
 * alone, and a retry never replays what else listens to the end of a session.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class QueueLogoutTokenHandler implements LogoutChannelInterface
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    /**
     * What puts a logout token on its way is what makes the provider a back-channel one, so it is what
     * the discovery document reads (issue #98).
     */
    public function channel(): LogoutChannel
    {
        return LogoutChannel::BackChannel;
    }

    public function __invoke(LogoutTokenIssued $event): void
    {
        $this->commandBus->dispatch(new SendLogoutToken(
            $event->tenant,
            $event->clientId,
            $event->logoutUri->value,
            $event->token,
            $event->sessionId,
            $event->subject,
            $event->context,
        ));
    }
}
