<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * Something that happened, announced after the command that caused it has committed. Routed to the low-priority AMQP transport; having no handler is allowed.
 */
interface Event
{
}
