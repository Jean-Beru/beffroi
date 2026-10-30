<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a person agreed to let a client obtain, by the name of a claim (issue #827): the claims a request
 * asked for one by one (OIDC Core §5.5) that no scope of it stood for, one JSON array in one column of the
 * consent.
 *
 * `DEFAULT '[]'`, so a consent a deployment already holds speaks the column the day it appears, and says
 * what it would have said: it was asked for no claim by name, the page never having listed one. A request
 * that names a claim beyond its scopes is asked again, which is what a consent that holds none must answer.
 *
 * It holds no personal datum and is not sealed: it names claims, never their values.
 */
final class Version20261030120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The claims a person agreed to by name, per consent (issue #827).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql("ALTER TABLE beffroi_consent ADD claims JSON DEFAULT '[]' NOT NULL");
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_consent DROP claims');
    }
}
