<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Which pushed authorization request an interaction was started from (RFC 9126 §4). The reference is
 * spent when the request it carries is granted and not when the authorization endpoint reads it
 * (FAPI 2.0 Security Profile §5.3.1), so the interaction has to remember which record to spend.
 */
final class Version20260923190000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The pushed authorization request an interaction was started from.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_interaction ADD request_uri_hash CHAR(64) DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_interaction DROP request_uri_hash');
    }
}
