<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The ticket that lets one person reach one enrolment without a session (issue #613): one table, the
 * identifier the URL carries, a hash of the value it carries beside it, and the dates that say whether it
 * still opens anything.
 *
 * The column of the value holds a hash and never a value, as the one of a password does, so a dump of this
 * table opens nothing. Two indexes: the one the sweep of the dead rows reads, oldest first, and the one
 * the issuing of a new ticket reads of a person, which takes away the unspent ones.
 */
final class Version20261011170000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The ticket that opens one enrolment without a session (issue #613).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_enrolment_ticket (id UUID NOT NULL, tenant_id UUID NOT NULL, user_id UUID NOT NULL, secret JSONB NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, spent_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_25C3F4C79033212A ON beffroi_enrolment_ticket (tenant_id)');
        $this->addSql('CREATE INDEX beffroi_enrolment_ticket_expiry ON beffroi_enrolment_ticket (tenant_id, expires_at)');
        $this->addSql('CREATE INDEX beffroi_enrolment_ticket_user ON beffroi_enrolment_ticket (user_id)');
        $this->addSql('ALTER TABLE beffroi_enrolment_ticket ADD CONSTRAINT FK_25C3F4C79033212A FOREIGN KEY (tenant_id) REFERENCES beffroi_tenant (id)');
        $this->addSql('ALTER TABLE beffroi_enrolment_ticket ADD CONSTRAINT FK_25C3F4C7A76ED395 FOREIGN KEY (user_id) REFERENCES beffroi_user (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_enrolment_ticket');
    }
}
