<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * A write the application asks for. Routed to the medium-priority AMQP transport unless listed as a synchronous exception in messenger.yaml.
 */
interface Command
{
}
