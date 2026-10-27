<?php

declare(strict_types=1);

namespace Beffroi\Bundle\EndSession;

use function ceil;
use DateInterval;
use Beffroi\Bundle\Http\LogoutTokenSender;
use Beffroi\Bundle\Messenger\NotificationRetryPolicy;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;

/**
 * How long a logout token stays on its way, from what carries it (Back-Channel Logout 1.0 §2.5): the
 * waits of the retry policy of its lane, plus the seconds each attempt is given before it counts as a
 * failure. Both are read where they are set, the policy and the sender, so that what a signing key is
 * held back for is what the provider actually does (issue #155).
 *
 * It counts the sends and their waits, not the time the message spent in the queue before the first one:
 * how far behind a lane is runs in the queue, is seen there, and is a fact of the deployment.
 */
final readonly class LogoutTokenDeliveryBudget implements LogoutTokenDeliveryInterface
{
    public function __construct(
        private NotificationRetryPolicy $retries,
        private LogoutTokenSender $sender,
    ) {
    }

    public function deliveryBudget(): DateInterval
    {
        $seconds = $this->retries->waiting() + (int) ceil($this->retries->attempts() * $this->sender->timeout->seconds);

        return new DateInterval('PT' . $seconds . 'S');
    }
}
