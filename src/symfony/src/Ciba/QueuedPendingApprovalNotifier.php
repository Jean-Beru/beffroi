<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Ciba;

use Beffroi\Bundle\Message\TellUserOfPendingApproval;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use Beffroi\Oidc\Port\PendingApprovalNotifierInterface;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * How the bundle reaches a user: by not doing it in the request (architecture §5.6). The client that made
 * the backchannel request is answered with an identifier and a lifetime, and what has to reach somebody
 * goes on the notifications lane, where it is tried again for as long as that lane is patient and given
 * up on after, exactly as a logout token is.
 *
 * The lane is the implementation and not the channel: what carries the word to the user at the end of it
 * is whatever the deployment wired there (PendingApprovalChannelInterface), and a deployment that wired
 * nothing still serves this flow, the user finding the request on the page where requests are answered.
 */
final readonly class QueuedPendingApprovalNotifier implements PendingApprovalNotifierInterface
{
    public function __construct(
        private MessageBusInterface $commandBus,
    ) {
    }

    public function tell(PendingApproval $approval): void
    {
        $this->commandBus->dispatch(new TellUserOfPendingApproval($approval));
    }
}
