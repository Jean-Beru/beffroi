<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a list of compromised passwords said of a password, on the password (issue #552).
 *
 * Two dates: when the list was last asked about it, and when it was found there. Both null for a password
 * nobody has asked about yet, which is every password this provider already holds, so the first login past
 * the delay is what asks about each of them.
 */
final class Version20261010180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'When a list of compromised passwords was asked about a password, and when it was found there (issue #552).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_password_credential ADD breach_checked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('ALTER TABLE beffroi_password_credential ADD breach_found_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_password_credential DROP breach_checked_at');
        $this->addSql('ALTER TABLE beffroi_password_credential DROP breach_found_at');
    }
}
