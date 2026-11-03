<?php

declare(strict_types=1);

namespace App\Messenger;

use Symfony\Component\Messenger\Exception\RecoverableMessageHandlingException;

/**
 * A notification that did not reach the party it is addressed to this time (architecture §5.6): a client
 * or a push service that failed in a way the next attempt may not, or that did not answer at all. A
 * handler of the notifications lane, or a channel it calls, throws it, and the worker brings the message
 * back on the policy of the lane (NotificationRetryPolicy) until that policy runs out; the message then
 * goes to the failure transport, and a logout token is said to be given up on (LogoutTokenGivenUpListener).
 *
 * The one thing it says beyond its parent is that the policy decides. Messenger brings a recoverable
 * exception back whatever the retry strategy of its transport says, unless the exception says otherwise
 * (forceRetry, true by default): a party that is gone would be sent the same notification again at each
 * longest wait of the policy, without end, and never be given up on.
 */
final class NotificationNotDeliveredException extends RecoverableMessageHandlingException
{
    public function __construct(string $detail)
    {
        parent::__construct($detail, forceRetry: false);
    }
}
