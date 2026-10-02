<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * The timed step of decision 0009: the clients that registered themselves and that nobody uses any more are
 * deleted, after the durations their tenant names. Recurring and idempotent: a tick that finds nothing due
 * does nothing, a run is bounded and what it leaves the next one takes, and a missed tick is caught up.
 */
final readonly class RemoveUnusedClients implements Command
{
}
