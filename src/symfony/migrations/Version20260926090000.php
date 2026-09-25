<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The device authorization requests (RFC 8628 §3.2): the code a client polls with as the key, the code its
 * user types under a unique constraint, what the request asked for, where the appliance asked from, and
 * what the user answered. Beside them, the origin of a refresh token family, which is now a record read
 * once of either kind and no longer an authorization code alone.
 */
final class Version20260926090000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The device authorization requests, and the refresh token family named after the record it descends from.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE heidi_device_authorization_request (device_code_hash CHAR(64) NOT NULL, user_code_hash CHAR(64) NOT NULL, client_id VARCHAR(255) NOT NULL, scopes TEXT NOT NULL, resources TEXT DEFAULT NULL, requested_from_received_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, requested_from_ip_address VARCHAR(45) DEFAULT NULL, requested_from_user_agent VARCHAR(1024) DEFAULT NULL, requested_from_location JSONB DEFAULT NULL, requested_from_device JSONB DEFAULT NULL, issued_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, poll_interval INT NOT NULL, last_polled_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, approved_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, denied_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, authentication JSONB DEFAULT NULL, used_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, tenant_id UUID NOT NULL, session_id UUID DEFAULT NULL, PRIMARY KEY (device_code_hash))');
        $this->addSql('CREATE UNIQUE INDEX heidi_device_authorization_user_code ON heidi_device_authorization_request (user_code_hash)');
        $this->addSql('CREATE INDEX heidi_device_authorization_expiry ON heidi_device_authorization_request (expires_at)');
        $this->addSql('CREATE INDEX IDX_62FCE4C79033212A ON heidi_device_authorization_request (tenant_id)');
        $this->addSql('CREATE INDEX IDX_62FCE4C7613FECDF ON heidi_device_authorization_request (session_id)');
        $this->addSql('ALTER TABLE heidi_device_authorization_request ADD CONSTRAINT FK_62FCE4C79033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_device_authorization_request ADD CONSTRAINT FK_62FCE4C7613FECDF FOREIGN KEY (session_id) REFERENCES heidi_authentication_session (id) ON DELETE CASCADE');

        $this->addSql('ALTER INDEX heidi_refresh_token_code RENAME TO heidi_refresh_token_granting_record');
        $this->addSql('ALTER TABLE heidi_refresh_token RENAME COLUMN family_authorization_code_hash TO family_granting_record_hash');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_refresh_token RENAME COLUMN family_granting_record_hash TO family_authorization_code_hash');
        $this->addSql('ALTER INDEX heidi_refresh_token_granting_record RENAME TO heidi_refresh_token_code');

        $this->addSql('ALTER TABLE heidi_device_authorization_request DROP CONSTRAINT FK_62FCE4C7613FECDF');
        $this->addSql('ALTER TABLE heidi_device_authorization_request DROP CONSTRAINT FK_62FCE4C79033212A');
        $this->addSql('DROP TABLE heidi_device_authorization_request');
    }
}
