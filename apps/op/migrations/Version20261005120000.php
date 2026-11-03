<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a tenant shows of itself on the pages of its provider besides its name (issue #449): the URL of its
 * logo and the two colours of its brand, one JSON document in one column.
 *
 * One column rather than three, because a look is read whole, by one object, and a page never asks for a
 * colour without the colour of what is written on it. Nothing queries a column of it either: the look of
 * the tenant of a request is read with the row of that tenant.
 *
 * `DEFAULT '{}'`, so that the row a deployment already has speaks the column the day it appears: an empty
 * document is a tenant that declared no look, which renders its pages exactly as they rendered before, and
 * it is what the mapping of the entity declares for the same reason the `acr` policy declares its own.
 *
 * It holds no personal datum and is not sealed: a name, a logo and two colours are what a page hands to
 * every visitor before anybody has signed in.
 */
final class Version20261005120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The logo and the colours a tenant gives its pages (issue #449).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql("ALTER TABLE beffroi_tenant ADD look JSON DEFAULT '{}' NOT NULL");
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_tenant DROP look');
    }
}
