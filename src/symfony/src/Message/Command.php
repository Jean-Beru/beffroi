<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * A write whose result the request does not need (architecture §5.6), routed to the medium-priority
 * transport. Never a SyncMessage as well: a message goes to every transport its types are routed to.
 */
interface Command
{
}
