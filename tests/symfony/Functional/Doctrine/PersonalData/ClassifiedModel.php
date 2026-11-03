<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use function array_key_exists;
use function array_keys;
use App\Doctrine\PersonalData\DataKeyColumns;
use App\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use function count;
use Doctrine\ORM\EntityManagerInterface;
use function is_a;
use function ksort;
use function sort;
use function sprintf;

/**
 * What the model declares of itself, read column by column: every entity answers for every field it
 * stores (`ClassifiedFieldsInterface`), the mappings of the provider say which column holds which field,
 * and the one table no class of the model holds a field of is classified by the provider that puts it in
 * the schema (`DataKeyColumns`).
 *
 * **An entity is asked for all of its fields**, the ones its parent's mapping declares included, which is
 * what makes a declaration something a use case can read whole: a class merges its parent's lines as it
 * inherits its mapping, and one that forgot to leaves the columns of that parent classified by nobody. A
 * column of an embeddable is asked of the object it comes from, which is the class whose mapping declares
 * the field.
 *
 * Nothing is inferred from a name. A column whose field no line names is named here with the field it
 * would have been declared on, and a line whose field no mapping gives a column is named here too, so
 * that `ClassifiedSchema` can refuse either without having to know how a field becomes a column.
 */
final readonly class ClassifiedModel
{
    /**
     * @param array<string, array<string, FieldClassificationInterface>> $columns table, then column
     * @param array<string, string> $unclassified the field behind every column no line names, by "table.column"
     * @param list<string> $linesWithNoColumn the lines no column carries, as "Class::$field"
     */
    public function __construct(
        private array $columns,
        private array $unclassified = [],
        private array $linesWithNoColumn = [],
    ) {
    }

    /**
     * The declaration of the model resolved against the mappings: a field is asked of the class the
     * mapping says declares it, which is the entity, the parent whose mapping the entity inherits, or the
     * object a column of an embeddable comes from.
     */
    public static function of(EntityManagerInterface $entityManager): self
    {
        $columns = [];
        $unclassified = [];
        $linesWithNoColumn = [];
        foreach ($entityManager->getMetadataFactory()->getAllMetadata() as $metadata) {
            $class = $metadata->getName();
            if (is_a($class, ClassifiedFieldsInterface::class, true)) {
                foreach (array_keys($class::classifiedFields()) as $field) {
                    if (! array_key_exists($field, $metadata->fieldMappings) && ! array_key_exists($field, $metadata->associationMappings)) {
                        $linesWithNoColumn[] = self::name($class, $field);
                    }
                }
            }
            if ($metadata->isMappedSuperclass || $metadata->isEmbeddedClass) {
                continue;
            }
            $table = $metadata->getTableName();
            foreach ($metadata->fieldMappings as $field => $mapping) {
                self::read(
                    $mapping->originalClass ?? $class,
                    $mapping->originalField ?? $field,
                    $table,
                    $metadata->getColumnName($field),
                    $columns,
                    $unclassified,
                );
            }
            foreach (array_keys($metadata->associationMappings) as $field) {
                if (! $metadata->isAssociationWithSingleJoinColumn($field)) {
                    continue;
                }
                self::read($class, $field, $table, $metadata->getSingleAssociationJoinColumnName($field), $columns, $unclassified);
            }
        }
        foreach (DataKeyColumns::classifiedFields() as $column => $line) {
            $columns[TenantDataKeyStores::TABLE][$column] = $line;
        }

        return new self($columns, $unclassified, $linesWithNoColumn);
    }

    /**
     * @return array<string, array<string, FieldClassificationInterface>> table, then column
     */
    public function columns(): array
    {
        return $this->columns;
    }

    /**
     * The lines of one table, by the column that holds them, which is how a test of that table reads what
     * its own columns are declared as.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public function linesOf(string $table): array
    {
        $lines = $this->columns[$table] ?? [];
        ksort($lines);

        return $lines;
    }

    /**
     * The field behind a column no line names, so that a finding says where the line goes.
     */
    public function fieldBehind(string $table, string $column): ?string
    {
        return $this->unclassified[sprintf('%s.%s', $table, $column)] ?? null;
    }

    /**
     * @return list<string> the lines no column of the schema carries, as "Class::$field"
     */
    public function linesWithNoColumn(): array
    {
        return $this->linesWithNoColumn;
    }

    /**
     * @return list<string> the tables the model classifies, in alphabetical order
     */
    public function tables(): array
    {
        $tables = array_keys($this->columns);
        sort($tables);

        return $tables;
    }

    /**
     * How many columns the model classifies, all tables together.
     */
    public function columnCount(): int
    {
        $total = 0;
        foreach ($this->columns as $columns) {
            $total += count($columns);
        }

        return $total;
    }

    /**
     * @param class-string $class
     * @param array<string, array<string, FieldClassificationInterface>> $columns
     * @param array<string, string> $unclassified
     */
    private static function read(string $class, string $field, string $table, string $column, array &$columns, array &$unclassified): void
    {
        $line = is_a($class, ClassifiedFieldsInterface::class, true) ? $class::classifiedFields()[$field] ?? null : null;
        if ($line === null) {
            $unclassified[sprintf('%s.%s', $table, $column)] = self::name($class, $field);

            return;
        }
        $columns[$table][$column] = $line;
    }

    private static function name(string $class, string $field): string
    {
        return sprintf('%s::$%s', $class, $field);
    }
}
