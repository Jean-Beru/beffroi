<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a pairwise subject identifier needs written down (OIDC Core §8.1): the identifier one sector of a
 * tenant has seen a user under.
 *
 * The value itself is computed, from the sector, the user and the salt of the tenant, so nothing here
 * decides it and a restore of this table alone changes no identifier. What it is for is the way back: a
 * "sub" a client presents is a hash, hashing goes one way, and the only way to answer who it names is to
 * have written it down when the document was issued.
 *
 * Both unique indexes say the same rule from its two sides, one identifier per user in a sector and one
 * user per identifier in it, which is also what lets two workers issuing the first two tokens of a user at
 * once write one row between them. The salt is not here and is in no migration: it is a secret of the
 * deployment, drawn once and kept sealed beside the keys of its tenant.
 */
final class Version20260930180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The identifier each sector of a tenant sees a user under (OIDC Core section 8.1).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_pairwise_subject (sector VARCHAR(255) NOT NULL, subject VARCHAR(255) NOT NULL, assigned_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, id UUID NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX beffroi_pairwise_subject_identifier ON beffroi_pairwise_subject (tenant_id, sector, subject)');
        $this->addSql('CREATE UNIQUE INDEX beffroi_pairwise_subject_user ON beffroi_pairwise_subject (tenant_id, sector, user_id)');
        $this->addSql('CREATE INDEX IDX_3D55F2529033212A ON beffroi_pairwise_subject (tenant_id)');
        $this->addSql('CREATE INDEX IDX_3D55F252A76ED395 ON beffroi_pairwise_subject (user_id)');
        $this->addSql('ALTER TABLE beffroi_pairwise_subject ADD CONSTRAINT FK_3D55F2529033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
        $this->addSql('ALTER TABLE beffroi_pairwise_subject ADD CONSTRAINT FK_3D55F252A76ED395 FOREIGN KEY (user_id) REFERENCES beffroi_user (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_pairwise_subject');
    }
}
