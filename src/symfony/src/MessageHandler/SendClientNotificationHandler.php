<?php

declare(strict_types=1);

namespace Heidi\Bundle\MessageHandler;

use Heidi\Bundle\Http\ClientNotificationSender;
use Heidi\Bundle\Message\SendClientNotification;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\Exception\RecoverableMessageHandlingException;

/**
 * Carries one notification to its client and says what became of it (CIBA Core §10.2). A client that
 * answered is done. A client that refused is given up on at once: retrying an answer that says "I read
 * this and I will not take it" gets the same answer, and the notification carries a credential of that
 * client, which is not presented again to somebody who has just rejected it. A client that could not be
 * reached makes this throw, so that Messenger brings the message back later under the retry policy of its
 * transport.
 *
 * Nothing of this holds the approval up: the request is answered at the provider whatever the client
 * believes, and a client that is never reached finds the same answer by polling the token endpoint, which
 * is what a client of the polling mode does from the start.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class SendClientNotificationHandler
{
    public function __construct(
        private ClientNotificationSender $sender,
    ) {
    }

    public function __invoke(SendClientNotification $message): void
    {
        $delivery = $this->sender->send($message->notificationEndpoint, $message->notificationToken, $message->authRequestId);
        if ($delivery->delivered || $delivery->final) {
            return;
        }

        throw new RecoverableMessageHandlingException($delivery->detail);
    }
}
