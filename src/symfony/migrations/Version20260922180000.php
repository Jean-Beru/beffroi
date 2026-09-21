<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Where an authorization request a client pushed waits for its user (RFC 9126 §2.2). The reference the
 * client holds is never stored, only its SHA-256, as an authorization code is; a used record stays until
 * it expires so that a second presentation is told from a reference nobody ever issued.
 */
final class Version20260922180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The pushed authorization requests.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE heidi_pushed_authorization_request (request_uri_hash CHAR(64) NOT NULL, client_id VARCHAR(255) NOT NULL, parameters JSONB NOT NULL, issued_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, used_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (request_uri_hash))');
        $this->addSql('CREATE INDEX IDX_624C72F59033212A ON heidi_pushed_authorization_request (tenant_id)');
        $this->addSql('ALTER TABLE heidi_pushed_authorization_request ADD CONSTRAINT FK_624C72F59033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE heidi_pushed_authorization_request');
    }
}
