<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\PersonalData;

use function array_key_exists;
use function array_keys;
use function count;
use function sort;
use function sprintf;

/**
 * The declaration of SchemaColumns held against the schema Doctrine builds, column by column.
 *
 * Nothing is inferred from a name: a column the declaration does not name is a finding, whichever list
 * would have been right for it, and a column the declaration names that the schema does not declare is
 * a finding too, so a line cannot outlive the column it was written for.
 */
final readonly class ClassifiedSchema
{
    /**
     * @param array<string, array<string, ColumnClassificationInterface>> $columns table, then column
     */
    public function __construct(
        private array $columns,
    ) {
    }

    /**
     * @param array<string, array<string, bool>> $schema table, then column, then whether its Doctrine type seals what it stores
     *
     * @return list<string> what the schema and the declaration disagree on, in alphabetical order, empty when they agree
     */
    public function findings(array $schema): array
    {
        $findings = [];
        foreach ($schema as $table => $columns) {
            foreach ($columns as $column => $sealed) {
                $name = sprintf('%s.%s', $table, $column);
                $line = $this->columns[$table][$column] ?? null;
                if ($line === null) {
                    $findings[] = sprintf(
                        '%s is in the schema and in no list: declare it readable with the reason a dump of it gives nothing away, sealed, or owed to the issue that seals it.',
                        $name,
                    );

                    continue;
                }
                $finding = $line->finding($name, $sealed);
                if ($finding !== null) {
                    $findings[] = $finding;
                }
            }
        }
        foreach ($this->columns as $table => $columns) {
            foreach (array_keys($columns) as $column) {
                if (! array_key_exists($column, $schema[$table] ?? [])) {
                    $findings[] = sprintf('%s.%s is classified and the schema does not declare it: delete its line.', $table, $column);
                }
            }
        }
        sort($findings);

        return $findings;
    }

    /**
     * @return list<string> the tables the declaration covers
     */
    public function tables(): array
    {
        return array_keys($this->columns);
    }

    /**
     * How many columns the declaration names, all tables together.
     */
    public function columnCount(): int
    {
        $total = 0;
        foreach ($this->columns as $columns) {
            $total += count($columns);
        }

        return $total;
    }
}
