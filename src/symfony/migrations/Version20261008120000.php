<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The archive a person asks for of everything this provider holds about them (RGPD articles 15 and 20,
 * issue #453): one row from the moment they ask, the document written into it later, off the request.
 *
 * `content` and `built_at` are nullable because an archive is asked for before it exists: a row without
 * them is an archive still being built, and a page that says so is what a person gets instead of nothing.
 *
 * `content` is sealed under the data key of the tenant, in a scope of its own (decisions 0011 and 0018).
 * It is the one column of this schema where everything the other families seal stands in clear at once,
 * and it carries no exemption for that.
 *
 * `expires_at` is set when the person asks and never moved, so every row carries the date it goes away on
 * whatever happened to its build. The second index is what the timed step reads, which walks by that date.
 */
final class Version20261008120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The archive a person asks for of everything the provider holds about them (issue #453).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_personal_archive (id UUID NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, asked_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, built_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, content BYTEA DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_9FE6FB219033212A ON beffroi_personal_archive (tenant_id)');
        $this->addSql('CREATE INDEX IDX_9FE6FB21A76ED395 ON beffroi_personal_archive (user_id)');
        $this->addSql('CREATE INDEX beffroi_personal_archive_person ON beffroi_personal_archive (user_id, asked_at)');
        $this->addSql('CREATE INDEX beffroi_personal_archive_expiry ON beffroi_personal_archive (tenant_id, expires_at)');
        $this->addSql('ALTER TABLE beffroi_personal_archive ADD CONSTRAINT FK_9FE6FB219033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE beffroi_personal_archive ADD CONSTRAINT FK_9FE6FB21A76ED395 FOREIGN KEY (user_id) REFERENCES beffroi_user (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_personal_archive');
    }
}
