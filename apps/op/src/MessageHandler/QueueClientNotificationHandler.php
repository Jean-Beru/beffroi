<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\SendClientNotification;
use Beffroi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * That a backchannel request was answered is a fact the audit reads; telling the client that made it is a
 * piece of work of its own (architecture §5.6). The hop is what keeps the two apart: the call is retried
 * on its own schedule and alone, and a retry never replays what else listens to an approval.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class QueueClientNotificationHandler
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function __invoke(BackchannelRequestAnswered $event): void
    {
        $this->commandBus->dispatch(new SendClientNotification(
            $event->tenant,
            $event->clientId,
            $event->notificationEndpoint->value,
            $event->notificationToken,
            $event->authRequestId,
            $event->context,
        ));
    }
}
