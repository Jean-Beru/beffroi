<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * The timed steps of the key lifecycle (architecture §3.3): activate the staged keys whose delay elapsed,
 * retire the keys past their retirement date. Recurring and idempotent: a tick that finds nothing due
 * does nothing, a missed tick is caught up by the next.
 */
final readonly class AdvanceKeyLifecycle implements Command
{
}
