<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The person a token whose subject a client named is in the name of (issue #593): one column beside the
 * "sub" the presented token carried.
 *
 * The "sub" of that row means something for the client the presented token was written for and for no
 * other, where the row names the client that asked: nothing can read it back here, so the acts of such a
 * token were written in nobody's name. The exchange had the person at hand when it read what was presented;
 * this is where it keeps it, in the clear as every other subject of this schema.
 *
 * Null on every row written before this, and on every row whose subject nothing read back as somebody this
 * provider serves, which is what a token a client holds for itself is (RFC 6749 section 4.4). A column and
 * no backfill: what the rows already written named cannot be resolved again, which is the reason the column
 * exists, and those tokens expire on their own.
 */
final class Version20261011150000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The person a token whose subject a client named is in the name of (issue #593).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_subject_access_token ADD person VARCHAR(255) DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_subject_access_token DROP person');
    }
}
