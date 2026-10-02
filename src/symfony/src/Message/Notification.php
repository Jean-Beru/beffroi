<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * Something the provider carries to a third party it does not own (architecture §5.6): a logout token to
 * a relying party today. A transport of its own, because what it waits for is not our database but
 * somebody else's server: it is tried again for longer, and it must not queue behind our own writes.
 * Never a Command nor a SyncMessage as well: a message goes to every transport its types are routed to.
 */
interface Notification
{
}
