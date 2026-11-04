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
 * Decisions 0011 and 0018
 */
final readonly class ProviderSchema
{
    private const string TABLE_PREFIX = 'beffroi_';

    private const string HOST_TABLE = 'app_user';

    /**
     * @param array<string, string> $sealingFamilies the family of each sealing type, by type name
     *
     * @return array<string, array<string, string|null>> table, then column, then its sealing family or null
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

    public static function familyOf(string $table): string
    {
        return str_starts_with($table, self::TABLE_PREFIX) ? substr($table, strlen(self::TABLE_PREFIX)) : $table;
    }
}
