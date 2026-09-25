<?php

declare(strict_types=1);

namespace Heidi\Bundle\Ciba;

use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Ciba\PendingApproval;

/**
 * One way an integration reaches a user of this deployment (architecture §5.6): a mail, a push
 * notification to an application of its own, a message on whatever it already uses to talk to them. One
 * class per way, tagged "heidi.pending_approval_channel", and a deployment that gains a way is a class
 * added to that wiring.
 *
 * The bundle ships none, and that is not an omission: how a deployment reaches its users is the one thing
 * about them it cannot be told in advance (decision 0002 owns the identity, this owns the reaching), and a
 * channel of our own would be a channel nobody wanted. A deployment that wires none is not broken either:
 * the user finds what is waiting for them on the page of the provider where requests are answered, which
 * is where every channel sends them anyway (BCP 10027 §5.2).
 *
 * This is called from the notifications lane and never in the request that made the client wait, so what
 * it does may be slow; what it must not do is throw for a user it cannot reach at all, which is not a
 * failure of the request.
 */
interface PendingApprovalChannelInterface
{
    public function tell(User $user, PendingApproval $approval): void;
}
