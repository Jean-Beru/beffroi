<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a claim of a person used to say, and what they made it say (issue #482): one row per change, so
 * that the question a person asks first when they read that they changed something has an answer.
 *
 * It is not the journal, which is four facts and two names and no column a caller fills: a value a person
 * said of themselves is a personal datum, and a value in the journal would be both a bag and a second
 * copy of that datum. The journal keeps saying that the act happened.
 *
 * `was`, `became` and `context` are sealed under the data key of the tenant, in a family of their own
 * (decisions 0011 and 0018). The two values are nullable: null on either side is a claim that said
 * nothing, which is a person filling one in or taking back what they had said.
 *
 * Two indexes, for the two questions asked of this table: the changes of one person, by an identifier
 * that sorts chronologically, and what is old enough to forget, which walks by the date of the change.
 */
final class Version20261009120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'What a claim of a person used to say, and what they made it say (issue #482).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_claim_change (id UUID NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, claim VARCHAR(64) NOT NULL, was BYTEA DEFAULT NULL, became BYTEA DEFAULT NULL, changed_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, context BYTEA NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_647F8D619033212A ON beffroi_claim_change (tenant_id)');
        $this->addSql('CREATE INDEX IDX_647F8D61A76ED395 ON beffroi_claim_change (user_id)');
        $this->addSql('CREATE INDEX beffroi_claim_change_person ON beffroi_claim_change (user_id, id)');
        $this->addSql('CREATE INDEX beffroi_claim_change_kept_until ON beffroi_claim_change (tenant_id, changed_at)');
        $this->addSql('ALTER TABLE beffroi_claim_change ADD CONSTRAINT FK_647F8D619033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE beffroi_claim_change ADD CONSTRAINT FK_647F8D61A76ED395 FOREIGN KEY (user_id) REFERENCES beffroi_user (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_claim_change');
    }
}
