<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

use function sprintf;

/**
 * A column whose Doctrine type seals what it stores, under the data key of its tenant and of its family
 * (decision 0018). The family is the scope that key is shared over, so two columns of one family share
 * one key and one unwrap.
 */
final readonly class Sealed implements ColumnClassificationInterface
{
    public function __construct(
        public string $family,
    ) {
    }

    public function finding(string $column, bool $sealed): ?string
    {
        return $sealed
            ? null
            : sprintf('%s is declared sealed under the "%s" family and its Doctrine type does not seal it.', $column, $this->family);
    }
}
