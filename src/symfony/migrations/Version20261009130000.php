<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function sprintf;

/**
 * What a session had proven at a grant goes in one column on the three tables that embedded it (issue
 * #440): `authenticated_at`, `amr` and `acr` become `authentication`, the JSON document the DBAL type
 * `beffroi_authentication_snapshot` reads back, which three other tables already carried that way.
 *
 * No row is moved. There is no deployment before this spike, so the three columns are dropped and the one
 * is added; a schema that held rows would have to write them across first, and none does.
 */
final class Version20261009130000 extends AbstractMigration
{
    private const array TABLES = [
        'beffroi_authorization_code',
        'beffroi_refresh_token',
        'beffroi_access_token',
    ];

    public function getDescription(): string
    {
        return 'What a session had proven at a grant, in one column on the three tables that embedded it (issue #440).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::TABLES as $table) {
            $this->addSql(sprintf('ALTER TABLE %s DROP authenticated_at', $table));
            $this->addSql(sprintf('ALTER TABLE %s DROP amr', $table));
            $this->addSql(sprintf('ALTER TABLE %s DROP acr', $table));
            $this->addSql(sprintf('ALTER TABLE %s ADD authentication JSONB NOT NULL', $table));
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::TABLES as $table) {
            $this->addSql(sprintf('ALTER TABLE %s DROP authentication', $table));
            $this->addSql(sprintf('ALTER TABLE %s ADD authenticated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL', $table));
            $this->addSql(sprintf('ALTER TABLE %s ADD amr TEXT NOT NULL', $table));
            $this->addSql(sprintf('ALTER TABLE %s ADD acr VARCHAR(255) NOT NULL', $table));
        }
    }
}
