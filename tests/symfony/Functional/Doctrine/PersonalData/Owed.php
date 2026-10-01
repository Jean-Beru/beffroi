<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

use function sprintf;

/**
 * A personal datum this spike seals and has not sealed yet, named with the issue that seals it, on the
 * model of the "known" list of CONFORMANCE_PLANS: the line says what is owed and who owes it, and the
 * day the column is found sealed the walk fails, so the line is deleted rather than carried.
 */
final readonly class Owed implements ColumnClassificationInterface
{
    public function __construct(
        public string $issue,
        public string $reason,
    ) {
    }

    public function finding(string $table, string $column, ?string $sealingType): ?string
    {
        return $sealingType === null
            ? null
            : sprintf('%s.%s is sealed and %s still owes it ("%s"): delete its line and declare it sealed.', $table, $column, $this->issue, $this->reason);
    }
}
