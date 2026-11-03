<?php

declare(strict_types=1);

namespace App\Message;

/**
 * The databases of addresses the enrichment of a provenance reads, brought up to date (issue #473).
 * Recurring and idempotent: a run that finds the versions it keeps costs MaxMind's redirect and an answer
 * that nothing changed, and no bytes, and a missed week is caught up by the next.
 *
 * A deployment that names no licence key has nothing to refresh, and a tick is not the place to say so.
 */
final readonly class RefreshTheAddressDatabases implements Command
{
}
