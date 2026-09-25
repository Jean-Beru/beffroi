<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

use Heidi\Oidc\Domain\Ciba\PendingApproval;

/**
 * One user to reach, because a client has asked for something they alone can answer (CIBA Core §7,
 * architecture §5.6). A Notification and not a Command: what it waits on is not our database but whatever
 * carries a message to somebody, on a transport of its own and with its own patience.
 *
 * It carries the approval whole, that object being written to leave the process: names, a date and a URL,
 * nothing that has to be resolved again on the other side, and nothing that would carry a reader straight
 * into an approval (BCP 10027 §5.2).
 */
final readonly class TellUserOfPendingApproval implements Notification
{
    public function __construct(
        public PendingApproval $approval,
    ) {
    }
}
