<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use function in_array;
use function ksort;

/**
 * The schema Doctrine builds from the mappings, in the terms SchemaColumns is written in: every table,
 * every column, and whether the Doctrine type the mapping gives that column seals what it stores.
 *
 * A sealing type is an EncryptedType of "symfony/doctrine-dbal-key-management" registered by the bundle,
 * which decorates the type the column would otherwise have carried and stores an envelope referring to
 * the data key of its scope (decision 0011, decision 0018). It is read by the name the mapping gives it,
 * and the names are the ones the bundle declares (EncryptedColumnTypes, read through
 * SchemaColumns::sealingTypes()). The two cannot drift apart: a column declared sealed whose type is not
 * one of those names is a finding, and so is a column whose type is one of them and whose line still owes
 * it.
 *
 * The name is carried and not reduced to a yes or no, because the name says which family the column seals
 * under and a column seals under its own table (`Sealed`): what a mapping cannot show is a column whose
 * type belongs to another table's scope, which is what an embeddable several entities embed produces.
 */
final readonly class BundleSchema
{
    /**
     * The table of the host application of the test kernel is not the bundle's to classify (decision
     * 0002), and it is the one table of this schema no mapping of the bundle describes.
     */
    private const string HOST_TABLE = 'app_user';

    /**
     * @param list<string> $sealingTypes names of the Doctrine types that seal what they store
     *
     * @return array<string, array<string, string|null>> table, then column, then the name of the encrypted
     *                                                   type its mapping gives it, or null when that type
     *                                                   does not seal
     */
    public static function columns(EntityManagerInterface $entityManager, array $sealingTypes): array
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
                $type = $column->getTypeName();
                $columns[$column->getObjectName()->getIdentifier()->getValue()] = in_array($type, $sealingTypes, true) ? $type : null;
            }
            ksort($columns);
            $tables[$name] = $columns;
        }
        ksort($tables);

        return $tables;
    }
}
