<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Oidc\Application\EndSession\BackChannelLogout;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Every session that ends is announced to the clients it signed in (Back-Channel Logout 1.0 §2.6), on
 * the event of the core rather than on the logout request, so that the user, a relying party and an
 * administrator all lead here (architecture §4.9, §5.6). Reaching its expiry does not end a session, so
 * the expiry announces nothing (decision 0031).
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class BackChannelLogoutHandler
{
    public function __construct(
        private BackChannelLogout $logout,
    ) {
    }

    public function __invoke(AuthenticationSessionEnded $event): void
    {
        $this->logout->sessionEnded($event->session, $event->context);
    }
}
