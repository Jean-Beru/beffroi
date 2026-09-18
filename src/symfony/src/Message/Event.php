<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * Something that happened, routed to the low-priority transport; no handler is allowed. The events of
 * the core reach the same bus through EventBusDispatcher, routed by DomainEventInterface.
 */
interface Event
{
}
