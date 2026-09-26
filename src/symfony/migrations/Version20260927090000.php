<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The opaque access tokens whose subject was named by what the client presented (RFC 8693 §2.1,
 * RFC 7523 §2.1): a token exchange and an assertion of a trusted issuer both hand out a token about somebody
 * the provider did not sign in, so the row keeps the "sub" as it was named, the sign-in the presented token
 * named as it named it, and the chain of actors that holds it.
 *
 * The session is a column and not a row: what named it is a token, which carries a "sid" and not a session.
 * Each kind of stored token keeps the columns of its own kind, so this is a table of its own beside the one of
 * a sign-in and the one of a client acting for itself.
 */
final class Version20260927090000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The opaque access tokens whose subject was named by what the client presented.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE heidi_subject_access_token (sub VARCHAR(255) NOT NULL, session_id UUID DEFAULT NULL, authentication JSONB DEFAULT NULL, act JSONB DEFAULT NULL, grant_id UUID NOT NULL, client_id VARCHAR(255) NOT NULL, scopes TEXT NOT NULL, resources TEXT DEFAULT NULL, cnf JSONB DEFAULT NULL, issued_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, token_hash CHAR(64) NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (token_hash))');
        $this->addSql('CREATE INDEX heidi_subject_access_token_grant ON heidi_subject_access_token (grant_id)');
        $this->addSql('CREATE INDEX heidi_subject_access_token_session ON heidi_subject_access_token (session_id)');
        $this->addSql('CREATE INDEX heidi_subject_access_token_expiry ON heidi_subject_access_token (expires_at)');
        $this->addSql('CREATE INDEX IDX_F2E82ABA9033212A ON heidi_subject_access_token (tenant_id)');
        $this->addSql('ALTER TABLE heidi_subject_access_token ADD CONSTRAINT FK_F2E82ABA9033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE heidi_subject_access_token');
    }
}
