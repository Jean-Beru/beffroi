<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a person may change of themselves, per tenant (issue #452): the names of the claims its people say
 * for themselves, one JSON array in one column.
 *
 * `DEFAULT '[]'`, so the row a deployment already has speaks the column the day it appears, and says what
 * it would have said: nothing is a person's to change until the tenant says which claims are. Opening one
 * is a decision somebody takes, where closing one would be a decision nobody took.
 *
 * It holds no personal datum and is not sealed: it names claims, never values and never a person.
 */
final class Version20261007120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'What a person may change of themselves, per tenant (issue #452).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql("ALTER TABLE beffroi_tenant ADD self_served_claims JSON DEFAULT '[]' NOT NULL");
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_tenant DROP self_served_claims');
    }
}
