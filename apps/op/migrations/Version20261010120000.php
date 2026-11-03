<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function array_keys;
use function sprintf;

/**
 * The four indexes the sweep of the dead rows reads (issue #177).
 *
 * Nothing removed a row that could no longer do anything, so no table was ever asked for its oldest rows
 * and no date of one was indexed for being read in that direction. The four tables here are the ones whose
 * expiry was not indexed already; the codes, the three kinds of opaque access token, the device requests
 * and the backchannel requests carry theirs since they were written.
 */
final class Version20261010120000 extends AbstractMigration
{
    /**
     * The index of each table, by the name the mapping gives it.
     */
    private const array EXPIRY_INDEXES = [
        'beffroi_authentication_session_expiry' => 'beffroi_authentication_session',
        'beffroi_interaction_expiry' => 'beffroi_interaction',
        'beffroi_pushed_authorization_expiry' => 'beffroi_pushed_authorization_request',
        'beffroi_refresh_token_family_expiry' => 'beffroi_refresh_token_family',
    ];

    public function getDescription(): string
    {
        return 'The four indexes the sweep of the dead rows reads (issue #177).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::EXPIRY_INDEXES as $index => $table) {
            $this->addSql(sprintf('CREATE INDEX %s ON %s (expires_at)', $index, $table));
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (array_keys(self::EXPIRY_INDEXES) as $index) {
            $this->addSql(sprintf('DROP INDEX %s', $index));
        }
    }
}
