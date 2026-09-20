<?php

declare(strict_types=1);

namespace Heidi\Bundle\MessageHandler;

use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Oidc\Application\EndSession\BackChannelLogout;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Every session that ends is announced to the clients it signed in (Back-Channel Logout 1.0 §2.6), on
 * the event of the core rather than on the logout request, so that the user, a relying party, an
 * administrator and the expiry all lead here (architecture §4.9, §5.6).
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
