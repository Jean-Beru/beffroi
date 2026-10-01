<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

use function sprintf;

/**
 * A column a dump gives away, and why that gives nothing away: the four reasons decision 0011 writes
 * down, and the few sentences of its own that no category says as well.
 *
 * The reason is a sentence and not a category, because a person reads it: the page for a RSSI
 * (issue #411) says what stays readable and why, and it says it from these lines.
 */
final readonly class NoPersonalDatum implements ColumnClassificationInterface
{
    public function __construct(
        public string $reason,
    ) {
    }

    /**
     * A readable column that turns out to be sealed is not a fault of the schema, it is a line that has
     * stopped being true: the column belongs to the sealed list from that day on.
     */
    public function finding(string $table, string $column, ?string $sealingType): ?string
    {
        return $sealingType === null
            ? null
            : sprintf('%s.%s is sealed, and is declared readable ("%s"): move its line to the sealed list.', $table, $column, $this->reason);
    }
}
