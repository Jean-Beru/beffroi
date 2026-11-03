<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use function ksort;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * The schema Doctrine builds from the mappings, in the terms a classified model is written in: every
 * table, every column, and the family what stores that column seals under, which is null when it does not
 * seal.
 *
 * A sealing type is an EncryptedType of "symfony/doctrine-dbal-key-management" registered by the provider,
 * which decorates the type the column would otherwise have carried and stores an envelope referring to
 * the data key of its scope (decision 0011, decision 0018). It is read by the name the mapping gives it,
 * and the family each of those names seals under is the provider's own declaration
 * (`EncryptedColumnTypes::familyByType()`); nothing is kept here beside it.
 *
 * The family is carried and not reduced to a yes or no, because a column seals under its own table
 * (`Sealed` of the core): what a mapping cannot show is a column whose type belongs to another table's
 * scope, which is what an embeddable several entities embed produces.
 */
final readonly class ProviderSchema
{
    /**
     * The prefix every table of the provider carries, which is what the name of a family is read without:
     * the rule `EncryptedColumnTypes` states when it says a family is read from the schema and never from
     * a second list.
     */
    private const string TABLE_PREFIX = 'beffroi_';

    /**
     * The table of the application of the test kernel is not the provider's to classify (decision
     * 0002).
     */
    private const string HOST_TABLE = 'app_user';

    /**
     * @param array<string, string> $sealingFamilies the family each sealing type seals under, by the name a
     *                                               mapping gives the type
     *
     * @return array<string, array<string, string|null>> table, then column, then the family what stores it
     *                                                   seals under, or null when it does not seal
     */
    public static function columns(EntityManagerInterface $entityManager, array $sealingFamilies): array
    {
        $schema = new SchemaTool($entityManager)->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata());
        $tables = [];
        foreach ($schema->getTables() as $table) {
            $name = $table->getObjectName()->getUnqualifiedName()->getValue();
            if ($name === self::HOST_TABLE) {
                continue;
            }
            $columns = [];
            foreach ($table->getColumns() as $column) {
                $columns[$column->getObjectName()->getIdentifier()->getValue()] = $sealingFamilies[$column->getTypeName()] ?? null;
            }
            ksort($columns);
            $tables[$name] = $columns;
        }
        ksort($tables);

        return $tables;
    }

    /**
     * The family a table seals under, which is its name without the prefix of the provider.
     */
    public static function familyOf(string $table): string
    {
        return str_starts_with($table, self::TABLE_PREFIX) ? substr($table, strlen(self::TABLE_PREFIX)) : $table;
    }
}
