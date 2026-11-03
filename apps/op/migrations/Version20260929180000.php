<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a client reads, replaces and deletes itself with (RFC 7592 §2.3): one column on the row of a client
 * this provider registered, holding the digest of the token and never the token.
 *
 * Its default is the digest of nothing, sixty-four zeroes, which no value hashes to: a client registered
 * before the column existed was handed no such token, so it reads itself with none, and a column that had
 * to be nullable for those rows would have been a column every comparison has to remember can be null.
 */
final class Version20260929180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The token a registered client reads, replaces and deletes itself with.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql("ALTER TABLE beffroi_client ADD registration_access_token CHAR(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL");
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_client DROP registration_access_token');
    }
}
