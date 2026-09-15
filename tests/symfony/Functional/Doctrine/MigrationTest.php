<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_filter;
use function array_map;
use function array_values;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\Exception\AbortMigration;
use Doctrine\Migrations\Query\Query;
use Doctrine\ORM\Tools\SchemaTool;
use Heidi\Bundle\Migrations\Version20260915171732;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use function sort;
use function str_contains;
use function str_starts_with;

/**
 * Architecture §5.3: the migration the bundle ships creates on PostgreSQL exactly what the mappings
 * describe, no more, no less. The platform is built from a declared server version, so that no
 * PostgreSQL is needed to check it; the application ran it against a real one.
 */
final class MigrationTest extends DatabaseTestCase
{
    #[Test]
    public function theMigrationCreatesWhatTheMappingsDescribeOnPostgreSql(): void
    {
        // Given
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]);
        $platform = $connection->getDatabasePlatform();
        static::assertInstanceOf(PostgreSQLPlatform::class, $platform);
        $entityManager = self::entityManager();
        $expected = array_values(array_filter(
            new SchemaTool($entityManager)
                ->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata())
                ->toSql($platform),
            static fn (string $statement): bool => ! str_contains($statement, 'app_user'),
        ));

        $migration = new Version20260915171732($connection, new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $actual = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        sort($expected);
        sort($actual);
        static::assertSame($expected, $actual);
    }

    #[Test]
    public function theMigrationCreatesTheElevenTablesOfTheBundle(): void
    {
        // Given
        $migration = new Version20260915171732(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        static::assertCount(11, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    #[Test]
    public function theMigrationRefusesAnotherPlatform(): void
    {
        // Given
        $migration = new Version20260915171732(self::entityManager()->getConnection(), new NullLogger());

        // Then
        $this->expectException(AbortMigration::class);

        // When
        $migration->up(new Schema());
    }
}
