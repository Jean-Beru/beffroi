<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * Something that happened, announced after the command that caused it has committed. Routed to the
 * low-priority AMQP transport; having no handler is allowed. The events of the core and of the module
 * do not implement this: they reach the same bus and the same transport through EventBusDispatcher, and
 * messenger.yaml routes them by their own interface (Heidi\Core\Domain\Event\DomainEventInterface).
 */
interface Event
{
}
