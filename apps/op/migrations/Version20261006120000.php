<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The journal of the acts of the provider (issue #454): who did what, when and from where, one row per
 * act, written off the request on the lane the events already travel.
 *
 * **Four facts and two names.** No column a caller fills with whatever it has, because that is the door a
 * secret eventually walks through; what an act concerns beyond the person and the client is read in the
 * rows of the thing itself.
 *
 * The identifier is a UUIDv7, which sorts chronologically, so the last acts of a person are a lookup on
 * the index and never a sort of their history. Two indexes, for the two questions asked of this table: the
 * acts of one person under a few names, and what is old enough to forget. The second walks by date and not
 * by identifier, so a row written late for an act that happened early is forgotten on the date of the act.
 *
 * `context` is sealed under the data key of the tenant, in a scope of its own (decisions 0011 and 0018):
 * it is what the request carried of a person, an address and a user agent. `subject` beside it is in the
 * clear, naming a person without saying anything about them, which is what lets a page of their account
 * find their own acts.
 */
final class Version20261006120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The journal of the acts of the provider (issue #454).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_journal (id UUID NOT NULL, tenant_id UUID NOT NULL, act VARCHAR(64) NOT NULL, occurred_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, context BYTEA NOT NULL, subject VARCHAR(255) DEFAULT NULL, client VARCHAR(255) DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_FAC380D39033212A ON beffroi_journal (tenant_id)');
        $this->addSql('CREATE INDEX beffroi_journal_person ON beffroi_journal (tenant_id, subject, act, id)');
        $this->addSql('CREATE INDEX beffroi_journal_kept_until ON beffroi_journal (tenant_id, occurred_at)');
        $this->addSql('ALTER TABLE beffroi_journal ADD CONSTRAINT FK_FAC380D39033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_journal');
    }
}
