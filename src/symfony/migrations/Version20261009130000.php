<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function sprintf;

/**
 * The embeddables of the mapping become one column each, read back by the DBAL type of their object
 * (issue #440).
 *
 * What a session had proven at a grant: `authenticated_at`, `amr` and `acr` become `authentication` on the
 * three tables that embedded it, the JSON document `beffroi_authentication_snapshot` reads back and which
 * three other tables already carried that way. The hash of a password credential: `hash_algorithm`,
 * `hash_encoded` and `hash_parameters` become `hash`, which `beffroi_password_hash` reads back with the
 * algorithm resolved as the class the wiring holds for its name.
 *
 * No row is moved. There is no deployment before this spike, so the old columns are dropped and the new
 * one is added; a schema that held rows would have to write them across first, and none does.
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
        return 'The embeddables of the mapping become one column each, read back by the DBAL type of their object (issue #440).';
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

        $this->addSql('ALTER TABLE beffroi_password_credential DROP hash_algorithm');
        $this->addSql('ALTER TABLE beffroi_password_credential DROP hash_encoded');
        $this->addSql('ALTER TABLE beffroi_password_credential DROP hash_parameters');
        $this->addSql('ALTER TABLE beffroi_password_credential ADD hash JSONB NOT NULL');
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

        $this->addSql('ALTER TABLE beffroi_password_credential DROP hash');
        $this->addSql('ALTER TABLE beffroi_password_credential ADD hash_algorithm VARCHAR(32) NOT NULL');
        $this->addSql('ALTER TABLE beffroi_password_credential ADD hash_encoded TEXT NOT NULL');
        $this->addSql('ALTER TABLE beffroi_password_credential ADD hash_parameters JSONB NOT NULL');
    }
}
