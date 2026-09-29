<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * When somebody last used a client this provider registered (decision 0009), and the index the timed step
 * that drops the clients nobody uses any more reads it by.
 *
 * The column is nullable, and null is not a missing value here: it is a client that has never been used,
 * which is not kept for as long as one used long ago. A client registered before the column existed is
 * therefore read as never used, which is what it looks like from the rows: nothing recorded a use of it.
 */
final class Version20260930120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'When a registered client was last used, and the index the removal of the unused ones reads.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_client ADD last_used_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('CREATE INDEX heidi_client_last_used ON heidi_client (tenant_id, last_used_at)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP INDEX heidi_client_last_used');
        $this->addSql('ALTER TABLE heidi_client DROP last_used_at');
    }
}
