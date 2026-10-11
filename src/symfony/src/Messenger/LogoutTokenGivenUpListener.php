<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Messenger;

use Beffroi\Bundle\Message\SendLogoutToken;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Messenger\Event\WorkerMessageFailedEvent;

/**
 * The end of the retries of a logout token (Back-Channel Logout 1.0 §2.8): the transport has brought the
 * message back as many times as its policy allows and the client never answered. What is given up on is
 * an event, not a silence, and it is the same event a refusal writes, so that the audit has one thing to
 * look for whatever the relying party did. The message still goes to the failure transport: the event
 * says it happened, the transport keeps what happened to it.
 */
final readonly class LogoutTokenGivenUpListener
{
    public function __construct(
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    #[AsEventListener(event: WorkerMessageFailedEvent::class)]
    public function __invoke(WorkerMessageFailedEvent $event): void
    {
        if ($event->willRetry()) {
            return;
        }
        $message = $event->getEnvelope()->getMessage();
        if (! $message instanceof SendLogoutToken) {
            return;
        }
        $this->events->dispatch(
            new LogoutTokenGivenUp(
                $this->clock->now(),
                $message->tenant,
                $message->context,
                $message->clientId,
                $message->subject,
                $message->sessionId,
                ExceptionTrail::of($event->getThrowable()),
            ),
        );
    }
}
