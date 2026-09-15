<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The first schema of the bundle (architecture §5.3): the eleven tables of the identity core and of the
 * OpenID Connect module, every one prefixed "heidi_", every one but the tenant carrying "tenant_id".
 * Generated from the XML mappings against PostgreSQL 16 and kept equal to them by a test; SQLite, the
 * platform of the functional tests, gets its schema from the mappings directly.
 */
final class Version20260915171732 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The tables of the identity core and of the OpenID Connect module.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE heidi_authentication_session (established_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, proofs JSONB NOT NULL, last_seen_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, ended_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, ended_by VARCHAR(32) DEFAULT NULL, id UUID NOT NULL, created_from_received_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, created_from_ip_address VARCHAR(45) DEFAULT NULL, created_from_user_agent VARCHAR(1024) DEFAULT NULL, created_from_location JSONB DEFAULT NULL, created_from_device JSONB DEFAULT NULL, last_seen_from_received_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, last_seen_from_ip_address VARCHAR(45) DEFAULT NULL, last_seen_from_user_agent VARCHAR(1024) DEFAULT NULL, last_seen_from_location JSONB DEFAULT NULL, last_seen_from_device JSONB DEFAULT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_7016CD4A9033212A ON heidi_authentication_session (tenant_id)');
        $this->addSql('CREATE INDEX IDX_7016CD4AA76ED395 ON heidi_authentication_session (user_id)');
        $this->addSql('CREATE TABLE heidi_authorization_code (client_id VARCHAR(255) NOT NULL, redirect_uri VARCHAR(2048) NOT NULL, scopes TEXT NOT NULL, nonce TEXT DEFAULT NULL, code_challenge VARCHAR(133) DEFAULT NULL, claims JSONB DEFAULT NULL, authenticated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, amr TEXT NOT NULL, acr VARCHAR(255) NOT NULL, issued_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, used_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, code_hash CHAR(64) NOT NULL, tenant_id UUID NOT NULL, session_id UUID NOT NULL, PRIMARY KEY (code_hash))');
        $this->addSql('CREATE INDEX heidi_authorization_code_expiry ON heidi_authorization_code (expires_at)');
        $this->addSql('CREATE INDEX IDX_2AE948189033212A ON heidi_authorization_code (tenant_id)');
        $this->addSql('CREATE INDEX IDX_2AE94818613FECDF ON heidi_authorization_code (session_id)');
        $this->addSql('CREATE TABLE heidi_consent (client_id VARCHAR(255) NOT NULL, scopes TEXT NOT NULL, granted_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, revoked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, id UUID NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX heidi_consent_user_client ON heidi_consent (user_id, client_id)');
        $this->addSql('CREATE INDEX IDX_9A5859E59033212A ON heidi_consent (tenant_id)');
        $this->addSql('CREATE INDEX IDX_9A5859E5A76ED395 ON heidi_consent (user_id)');
        $this->addSql('CREATE TABLE heidi_group (name VARCHAR(255) NOT NULL, source VARCHAR(32) NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, id UUID NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_group_name ON heidi_group (tenant_id, name)');
        $this->addSql('CREATE INDEX IDX_5A2B90D79033212A ON heidi_group (tenant_id)');
        $this->addSql('CREATE TABLE heidi_group_membership (source VARCHAR(32) NOT NULL, added_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, id UUID NOT NULL, tenant_id UUID NOT NULL, group_id UUID NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_group_membership_member ON heidi_group_membership (group_id, user_id)');
        $this->addSql('CREATE INDEX IDX_C639A45C9033212A ON heidi_group_membership (tenant_id)');
        $this->addSql('CREATE INDEX IDX_C639A45CFE54D947 ON heidi_group_membership (group_id)');
        $this->addSql('CREATE INDEX IDX_C639A45CA76ED395 ON heidi_group_membership (user_id)');
        $this->addSql('CREATE TABLE heidi_interaction (client_id VARCHAR(255) NOT NULL, locale VARCHAR(35) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, completed_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, id CHAR(43) NOT NULL, redirect_uri VARCHAR(2048) NOT NULL, scopes TEXT NOT NULL, code_challenge VARCHAR(133) DEFAULT NULL, state TEXT DEFAULT NULL, nonce TEXT DEFAULT NULL, prompts JSONB NOT NULL, max_age INT DEFAULT NULL, login_hint TEXT DEFAULT NULL, ui_locales JSONB NOT NULL, acr_values JSONB NOT NULL, display VARCHAR(8) DEFAULT NULL, id_token_hint TEXT DEFAULT NULL, claims JSONB DEFAULT NULL, response_mode VARCHAR(16) NOT NULL, tenant_id UUID NOT NULL, session_id UUID DEFAULT NULL, consent_id UUID DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_25BCB2829033212A ON heidi_interaction (tenant_id)');
        $this->addSql('CREATE INDEX IDX_25BCB282613FECDF ON heidi_interaction (session_id)');
        $this->addSql('CREATE INDEX IDX_25BCB28241079D63 ON heidi_interaction (consent_id)');
        $this->addSql('CREATE TABLE heidi_linked_identity (provider VARCHAR(255) NOT NULL, subject VARCHAR(255) NOT NULL, claims JSONB NOT NULL, linked_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, last_seen_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, id UUID NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_linked_identity_subject ON heidi_linked_identity (tenant_id, provider, subject)');
        $this->addSql('CREATE INDEX IDX_DD5B44109033212A ON heidi_linked_identity (tenant_id)');
        $this->addSql('CREATE INDEX IDX_DD5B4410A76ED395 ON heidi_linked_identity (user_id)');
        $this->addSql('CREATE TABLE heidi_password_credential (created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, last_used_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, id UUID NOT NULL, hash_changed_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, hash_algorithm VARCHAR(32) NOT NULL, hash_encoded TEXT NOT NULL, hash_parameters JSONB NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_password_credential_user ON heidi_password_credential (user_id)');
        $this->addSql('CREATE INDEX IDX_657D1B29033212A ON heidi_password_credential (tenant_id)');
        $this->addSql('CREATE TABLE heidi_refresh_token (client_id VARCHAR(255) NOT NULL, scopes TEXT NOT NULL, claims JSONB DEFAULT NULL, authenticated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, amr TEXT NOT NULL, acr VARCHAR(255) NOT NULL, issued_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, rotated_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, revoked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, token_hash CHAR(64) NOT NULL, family_id UUID NOT NULL, family_authorization_code_hash CHAR(64) NOT NULL, family_started_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, family_expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, tenant_id UUID NOT NULL, session_id UUID NOT NULL, PRIMARY KEY (token_hash))');
        $this->addSql('CREATE INDEX heidi_refresh_token_family ON heidi_refresh_token (family_id)');
        $this->addSql('CREATE INDEX heidi_refresh_token_code ON heidi_refresh_token (family_authorization_code_hash)');
        $this->addSql('CREATE INDEX IDX_C9DFBF429033212A ON heidi_refresh_token (tenant_id)');
        $this->addSql('CREATE INDEX IDX_C9DFBF42613FECDF ON heidi_refresh_token (session_id)');
        $this->addSql('CREATE TABLE heidi_tenant (slug VARCHAR(63) NOT NULL, issuer VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_tenant_slug ON heidi_tenant (slug)');
        $this->addSql('CREATE UNIQUE INDEX heidi_tenant_issuer ON heidi_tenant (issuer)');
        $this->addSql('CREATE TABLE heidi_user (subject VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, email VARCHAR(255) DEFAULT NULL, email_verified BOOLEAN NOT NULL, phone_number VARCHAR(64) DEFAULT NULL, phone_number_verified BOOLEAN NOT NULL, address JSONB DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, disabled_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, id UUID NOT NULL, name VARCHAR(255) DEFAULT NULL, given_name VARCHAR(255) DEFAULT NULL, family_name VARCHAR(255) DEFAULT NULL, middle_name VARCHAR(255) DEFAULT NULL, nickname VARCHAR(255) DEFAULT NULL, preferred_username VARCHAR(255) DEFAULT NULL, profile_url TEXT DEFAULT NULL, picture_url TEXT DEFAULT NULL, website_url TEXT DEFAULT NULL, gender VARCHAR(64) DEFAULT NULL, birthdate VARCHAR(10) DEFAULT NULL, zoneinfo VARCHAR(64) DEFAULT NULL, locale VARCHAR(35) DEFAULT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX heidi_user_subject ON heidi_user (tenant_id, subject)');
        $this->addSql('CREATE UNIQUE INDEX heidi_user_username ON heidi_user (tenant_id, username)');
        $this->addSql('CREATE INDEX IDX_BE7C34A29033212A ON heidi_user (tenant_id)');
        $this->addSql('ALTER TABLE heidi_authentication_session ADD CONSTRAINT FK_7016CD4A9033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_authentication_session ADD CONSTRAINT FK_7016CD4AA76ED395 FOREIGN KEY (user_id) REFERENCES heidi_user (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_authorization_code ADD CONSTRAINT FK_2AE948189033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_authorization_code ADD CONSTRAINT FK_2AE94818613FECDF FOREIGN KEY (session_id) REFERENCES heidi_authentication_session (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_consent ADD CONSTRAINT FK_9A5859E59033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_consent ADD CONSTRAINT FK_9A5859E5A76ED395 FOREIGN KEY (user_id) REFERENCES heidi_user (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_group ADD CONSTRAINT FK_5A2B90D79033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_group_membership ADD CONSTRAINT FK_C639A45C9033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_group_membership ADD CONSTRAINT FK_C639A45CFE54D947 FOREIGN KEY (group_id) REFERENCES heidi_group (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_group_membership ADD CONSTRAINT FK_C639A45CA76ED395 FOREIGN KEY (user_id) REFERENCES heidi_user (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_interaction ADD CONSTRAINT FK_25BCB2829033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_interaction ADD CONSTRAINT FK_25BCB282613FECDF FOREIGN KEY (session_id) REFERENCES heidi_authentication_session (id) ON DELETE SET NULL');
        $this->addSql('ALTER TABLE heidi_interaction ADD CONSTRAINT FK_25BCB28241079D63 FOREIGN KEY (consent_id) REFERENCES heidi_consent (id) ON DELETE SET NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD CONSTRAINT FK_DD5B44109033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD CONSTRAINT FK_DD5B4410A76ED395 FOREIGN KEY (user_id) REFERENCES heidi_user (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_password_credential ADD CONSTRAINT FK_657D1B29033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_password_credential ADD CONSTRAINT FK_657D1B2A76ED395 FOREIGN KEY (user_id) REFERENCES heidi_user (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_refresh_token ADD CONSTRAINT FK_C9DFBF429033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
        $this->addSql('ALTER TABLE heidi_refresh_token ADD CONSTRAINT FK_C9DFBF42613FECDF FOREIGN KEY (session_id) REFERENCES heidi_authentication_session (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE heidi_user ADD CONSTRAINT FK_BE7C34A29033212A FOREIGN KEY (tenant_id) REFERENCES heidi_tenant (id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_authentication_session DROP CONSTRAINT FK_7016CD4A9033212A');
        $this->addSql('ALTER TABLE heidi_authentication_session DROP CONSTRAINT FK_7016CD4AA76ED395');
        $this->addSql('ALTER TABLE heidi_authorization_code DROP CONSTRAINT FK_2AE948189033212A');
        $this->addSql('ALTER TABLE heidi_authorization_code DROP CONSTRAINT FK_2AE94818613FECDF');
        $this->addSql('ALTER TABLE heidi_consent DROP CONSTRAINT FK_9A5859E59033212A');
        $this->addSql('ALTER TABLE heidi_consent DROP CONSTRAINT FK_9A5859E5A76ED395');
        $this->addSql('ALTER TABLE heidi_group DROP CONSTRAINT FK_5A2B90D79033212A');
        $this->addSql('ALTER TABLE heidi_group_membership DROP CONSTRAINT FK_C639A45C9033212A');
        $this->addSql('ALTER TABLE heidi_group_membership DROP CONSTRAINT FK_C639A45CFE54D947');
        $this->addSql('ALTER TABLE heidi_group_membership DROP CONSTRAINT FK_C639A45CA76ED395');
        $this->addSql('ALTER TABLE heidi_interaction DROP CONSTRAINT FK_25BCB2829033212A');
        $this->addSql('ALTER TABLE heidi_interaction DROP CONSTRAINT FK_25BCB282613FECDF');
        $this->addSql('ALTER TABLE heidi_interaction DROP CONSTRAINT FK_25BCB28241079D63');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP CONSTRAINT FK_DD5B44109033212A');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP CONSTRAINT FK_DD5B4410A76ED395');
        $this->addSql('ALTER TABLE heidi_password_credential DROP CONSTRAINT FK_657D1B29033212A');
        $this->addSql('ALTER TABLE heidi_password_credential DROP CONSTRAINT FK_657D1B2A76ED395');
        $this->addSql('ALTER TABLE heidi_refresh_token DROP CONSTRAINT FK_C9DFBF429033212A');
        $this->addSql('ALTER TABLE heidi_refresh_token DROP CONSTRAINT FK_C9DFBF42613FECDF');
        $this->addSql('ALTER TABLE heidi_user DROP CONSTRAINT FK_BE7C34A29033212A');
        $this->addSql('DROP TABLE heidi_authentication_session');
        $this->addSql('DROP TABLE heidi_authorization_code');
        $this->addSql('DROP TABLE heidi_consent');
        $this->addSql('DROP TABLE heidi_group');
        $this->addSql('DROP TABLE heidi_group_membership');
        $this->addSql('DROP TABLE heidi_interaction');
        $this->addSql('DROP TABLE heidi_linked_identity');
        $this->addSql('DROP TABLE heidi_password_credential');
        $this->addSql('DROP TABLE heidi_refresh_token');
        $this->addSql('DROP TABLE heidi_tenant');
        $this->addSql('DROP TABLE heidi_user');
    }
}
