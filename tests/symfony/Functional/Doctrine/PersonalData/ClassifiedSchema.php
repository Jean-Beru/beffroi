<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

use function array_key_exists;
use function array_keys;
use Beffroi\Core\Domain\PersonalData\StoredField;
use function sort;
use function sprintf;

/**
 * The classification the model declares held against the schema Doctrine builds, column by column.
 *
 * The declaration is the model's own and this reads it (`ClassifiedModel`): a column the model does not
 * classify is a finding, whichever line would have been right for it, and a line the schema gives no
 * column is a finding too, so neither side outlives the other. What each line has to say about the column
 * it was written for is the line's own answer (`FieldClassificationInterface`), the family of a sealed
 * column being its own table.
 */
final readonly class ClassifiedSchema
{
    public function __construct(
        private ClassifiedModel $model,
    ) {
    }

    /**
     * @param array<string, array<string, string|null>> $schema table, then column, then the family what
     *                                                          stores that column seals under, or null when
     *                                                          it does not seal
     *
     * @return list<string> what the schema and the model disagree on, in alphabetical order, empty when they agree
     */
    public function findings(array $schema): array
    {
        $findings = [];
        $classified = $this->model->columns();
        foreach ($schema as $table => $columns) {
            foreach ($columns as $column => $sealedUnder) {
                $name = sprintf('%s.%s', $table, $column);
                $line = $classified[$table][$column] ?? null;
                if ($line === null) {
                    $findings[] = sprintf(
                        '%s is in the schema and the model does not classify it: declare %s readable with the reason a dump of it gives nothing away, sealed under its family, a blind index, or owed to the issue that seals it.',
                        $name,
                        $this->model->fieldBehind($table, $column) ?? 'the field the class that holds it answers for',
                    );

                    continue;
                }
                $finding = $line->finding(new StoredField($name, BundleSchema::familyOf($table), $sealedUnder));
                if ($finding !== null) {
                    $findings[] = $finding;
                }
            }
        }
        foreach ($classified as $table => $columns) {
            foreach (array_keys($columns) as $column) {
                if (! array_key_exists($column, $schema[$table] ?? [])) {
                    $findings[] = sprintf('%s.%s is classified and the schema does not declare it: delete its line.', $table, $column);
                }
            }
        }
        foreach ($this->model->linesWithNoColumn() as $line) {
            $findings[] = sprintf('%s is classified and no column of the schema carries it: delete its line.', $line);
        }
        sort($findings);

        return $findings;
    }
}
