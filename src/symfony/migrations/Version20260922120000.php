<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What an opaque access token is bound to (RFC 8705 §3, architecture §4.6), stored as the "cnf" of
 * RFC 7800 §3.1 is written. A token issued before this migration is bound to nothing and stays a bearer
 * token until it expires, which is ten minutes.
 */
final class Version20260922120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The confirmation of a certificate-bound access token.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_access_token ADD cnf JSONB DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_access_token DROP cnf');
    }
}
