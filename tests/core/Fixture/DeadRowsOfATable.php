<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use DateTimeImmutable;
use function min;

/**
 * A store of dead rows, as a test reads it (issue #177): it holds a number of rows it may drop, drops at
 * most what it is given, and remembers what it was asked. A double of the port and not an adapter of the
 * Bridge, what a row of a real table is worth being the store's own answer and never this one's.
 */
final class DeadRowsOfATable implements DeadRecordsInterface
{
    public private(set) int $asked = 0;

    public private(set) ?int $limitAsked = null;

    public private(set) ?DateTimeImmutable $instantAsked = null;

    public function __construct(
        private int $dead = 0,
    ) {
    }

    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $this->asked++;
        $this->limitAsked = $limit;
        $this->instantAsked = $now;
        $forgotten = min($this->dead, $limit);
        $this->dead -= $forgotten;

        return $forgotten;
    }

    public function left(): int
    {
        return $this->dead;
    }
}
