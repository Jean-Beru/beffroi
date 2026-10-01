<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

use Heidi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * A column whose Doctrine type seals what it stores, under the data key of its tenant and of its family
 * (decision 0018). The family is the scope that key is shared over, so two columns of one family share
 * one key and one unwrap.
 *
 * **A sealed column seals under its own table**, and that is the one thing this line checks beyond the
 * sealing itself. The family is the name of the table without the prefix of the bundle, so a column
 * sealed under another family is a column written into the scope of a table that is not its own, which no
 * destruction of its tenant's keys for that table would reach. Two shapes of the mapping can do it: a
 * family typed wrong in a mapping, and an embeddable, which fixes the type of each of its fields once for
 * the whole model and whose columns land on every entity that embeds it (`AuthorizationRequest` carries
 * the two hints of a request and is embedded by `Interaction` alone, which is what makes its sealed type
 * right). Neither is visible in the mapping that would be wrong, so it is read here.
 */
final readonly class Sealed implements ColumnClassificationInterface
{
    private const string TABLE_PREFIX = 'heidi_';

    public function __construct(
        public string $family,
    ) {
    }

    public function finding(string $table, string $column, ?string $sealingType): ?string
    {
        if ($sealingType === null) {
            return sprintf(
                '%s.%s is declared sealed under the "%s" family and its Doctrine type does not seal it.',
                $table,
                $column,
                $this->family,
            );
        }

        $expected = self::familyOf($table);
        if ($this->family !== $expected) {
            return sprintf(
                '%s.%s is declared sealed under the "%s" family, and a column seals under its own table, so under "%s".',
                $table,
                $column,
                $this->family,
                $expected,
            );
        }

        if (! str_starts_with($sealingType, EncryptedColumnTypes::PREFIX . $this->family . '_')) {
            return sprintf(
                '%s.%s is declared sealed under the "%s" family and carries "%s", which seals under another: a column of an embeddable several entities embed cannot carry the type of one of their tables.',
                $table,
                $column,
                $this->family,
                $sealingType,
            );
        }

        return null;
    }

    /**
     * The family a table seals under, which is its name without the prefix every table of the bundle
     * carries: the rule `EncryptedColumnTypes` states when it says a family is read from the schema and
     * never from a second list.
     */
    public static function familyOf(string $table): string
    {
        return str_starts_with($table, self::TABLE_PREFIX) ? substr($table, strlen(self::TABLE_PREFIX)) : $table;
    }
}
