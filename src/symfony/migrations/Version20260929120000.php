<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What the controlled registration mode of decision 0009 needs: the initial access tokens a tenant
 * issues (RFC 7591 §1.2), and what the registration policy of a tenant wrote on a client it registered
 * (decision 0017).
 *
 * A token is one row holding the digest of its value and never the value, so that whoever reads the
 * table holds nothing to present; the digest is unique under its tenant, which is what a presented value
 * is looked up by and what makes one registration of it claimable by one request. What the policy wrote
 * is its own column beside the metadata the client sent: the two would otherwise be one column a client
 * could write half of, and a row written before this migration had no policy writing on it.
 */
final class Version20260929120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The initial access tokens of a tenant, and what a registration policy writes on a client.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE heidi_initial_access_token (digest CHAR(64) NOT NULL, name VARCHAR(255) NOT NULL, registrations_allowed INT NOT NULL, registrations_served INT NOT NULL, issued_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, revoked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, id UUID NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_initial_access_token_digest ON heidi_initial_access_token (tenant_id, digest)');
        $this->addSql('CREATE INDEX IDX_D63D3019033212A ON heidi_initial_access_token (tenant_id)');
        $this->addSql('ALTER TABLE heidi_initial_access_token ADD CONSTRAINT FK_D63D3019033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql("ALTER TABLE heidi_client ADD assigned_metadata JSONB DEFAULT '{}' NOT NULL");
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_client DROP assigned_metadata');
        $this->addSql('DROP TABLE heidi_initial_access_token');
    }
}
