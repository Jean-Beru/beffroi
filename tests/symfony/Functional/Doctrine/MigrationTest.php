<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_filter;
use function array_map;
use function array_values;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\Exception\AbortMigration;
use Doctrine\Migrations\Query\Query;
use Doctrine\ORM\Tools\SchemaTool;
use Heidi\Bundle\Migrations\Version20260915171732;
use Heidi\Bundle\Migrations\Version20260917180000;
use Heidi\Bundle\Migrations\Version20260919150000;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use function sort;
use function str_contains;
use function str_starts_with;

/**
 * Architecture §5.3: the migrations the bundle ships create on PostgreSQL exactly what the mappings
 * describe, no more, no less. The platform is built from a declared server version, so that no
 * PostgreSQL is needed to check it; the application ran them against a real one.
 */
final class MigrationTest extends DatabaseTestCase
{
    /**
     * The migrations, in the order they are applied.
     *
     * @return list<class-string<AbstractMigration>>
     */
    private const array MIGRATIONS = [Version20260915171732::class, Version20260917180000::class, Version20260919150000::class];

    #[Test]
    public function theMigrationsCreateWhatTheMappingsDescribeOnPostgreSql(): void
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

        // When
        $actual = self::statements($connection);

        // Then
        sort($expected);
        sort($actual);
        static::assertSame($expected, $actual);
    }

    #[Test]
    public function theMigrationsCreateTheThirteenTablesOfTheBundle(): void
    {
        // Given
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]);

        // When
        $statements = self::statements($connection);

        // Then
        static::assertCount(13, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    /**
     * The second migration adds the one table of the opaque access tokens and nothing else, so that a
     * deployment of spike 1 upgrades by one table.
     */
    #[Test]
    public function theSecondMigrationAddsTheAccessTokenTableAlone(): void
    {
        // Given
        $migration = new Version20260917180000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        foreach ($statements as $statement) {
            static::assertStringContainsString('heidi_access_token', $statement);
        }
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    /**
     * The third migration adds the one table of the passkeys and nothing else, so that a deployment of
     * spike 2 upgrades by one table.
     */
    #[Test]
    public function theThirdMigrationAddsThePasskeyTableAlone(): void
    {
        // Given
        $migration = new Version20260919150000(DriverManager::getConnection([
            'driver' => 'pdo_pgsql',
            'serverVersion' => '16',
        ]), new NullLogger());

        // When
        $migration->up(new Schema());

        // Then
        $statements = array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql());
        foreach ($statements as $statement) {
            static::assertStringContainsString('heidi_passkey_credential', $statement);
        }
        static::assertCount(1, array_filter($statements, static fn (string $statement): bool => str_starts_with($statement, 'CREATE TABLE ')));
    }

    /**
     * @param class-string<AbstractMigration> $migration
     */
    #[Test]
    #[DataProvider('provideMigrations')]
    public function everyMigrationRefusesAnotherPlatform(string $migration): void
    {
        // Given
        $migration = new $migration(self::entityManager()->getConnection(), new NullLogger());

        // Then
        $this->expectException(AbortMigration::class);

        // When
        $migration->up(new Schema());
    }

    /**
     * @return iterable<string, array{class-string<AbstractMigration>}>
     */
    public static function provideMigrations(): iterable
    {
        foreach (self::MIGRATIONS as $migration) {
            yield $migration => [$migration];
        }
    }

    /**
     * The statements of every migration, applied in order.
     *
     * @return list<string>
     */
    private static function statements(Connection $connection): array
    {
        $statements = [];
        foreach (self::MIGRATIONS as $class) {
            $migration = new $class($connection, new NullLogger());
            $migration->up(new Schema());
            $statements = [...$statements, ...array_values(array_map(static fn (Query $query): string => $query->getStatement(), $migration->getSql()))];
        }

        return $statements;
    }
}
