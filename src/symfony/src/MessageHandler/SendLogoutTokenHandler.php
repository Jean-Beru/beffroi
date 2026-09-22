<?php

declare(strict_types=1);

namespace Heidi\Bundle\MessageHandler;

use Heidi\Bundle\Http\LogoutTokenSender;
use Heidi\Bundle\Message\SendLogoutToken;
use Heidi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\Exception\RecoverableMessageHandlingException;

/**
 * Carries one logout token to its client and says what became of it (Back-Channel Logout 1.0 §2.8). A
 * client that answered is done. A client that refused is given up on at once, with an event: retrying a
 * 400 gets a 400. A client that could not be reached makes this throw, so that Messenger brings the
 * message back later under the retry policy of its transport; when that policy runs out, the worker says
 * so and LogoutTokenGivenUpListener writes the same event. Nothing of this reaches the user: the session
 * is already closed.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class SendLogoutTokenHandler
{
    public function __construct(
        private LogoutTokenSender $sender,
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(SendLogoutToken $message): void
    {
        $delivery = $this->sender->send($message->logoutUri, $message->logoutToken);
        if ($delivery->delivered) {
            return;
        }
        if (! $delivery->final) {
            throw new RecoverableMessageHandlingException($delivery->detail);
        }
        $this->events->dispatch(
            new LogoutTokenGivenUp($this->clock->now(), $message->tenant, $message->context, $message->clientId, $message->sessionId, $delivery->detail),
        );
    }
}
