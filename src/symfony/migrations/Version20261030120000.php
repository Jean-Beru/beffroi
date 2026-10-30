<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a software statement signed of a client (RFC 7591 §2.3, issue #830), kept beside what the client sent and
 * sealed under the data key of its tenant in the "client" family like the rest of the row (decisions 0011 and
 * 0018): a replacement is read from what the client sends (RFC 7592 §2.2), and what an authority signed is read in
 * front of it again from this column.
 *
 * Nullable, and null is a client no statement attested, which is said without the data key of the tenant: a
 * migration does not have it, and sealing a value would need it. The rows the table holds are read that way, what
 * a statement signed of one of them being among its metadata only, where a replacement writes.
 */
final class Version20261030120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'What a software statement signed of a client, kept beside what the client sent (issue #830).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_client ADD attested_metadata BYTEA DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_client DROP attested_metadata');
    }
}
