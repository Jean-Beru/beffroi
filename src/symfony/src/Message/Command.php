<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * A write the application asks for and does not need the result of in the same request: audit, enrichment,
 * rehash, purge, notification. Routed to the medium-priority AMQP transport by the application's
 * messenger.yaml. A write the protocol needs before answering is not a Command: it is a SyncMessage, or a
 * use case the controller calls directly (architecture §5.6). A message never implements both, because a
 * message is sent to every transport its types are routed to.
 */
interface Command
{
}
