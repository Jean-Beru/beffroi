<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a request reserves its code for (RFC 9449 §10) and what a refresh token of a public client is
 * bound to (§5). The authorization request carries the thumbprint of the key that will come and collect
 * the code, the code carries it in turn, and the refresh token carries the same "cnf" an access token
 * carries, because a client with no credentials is told from whoever copied its token by that and by
 * nothing else.
 */
final class Version20260923090000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The key an authorization is reserved for, and the binding of a refresh token.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_interaction ADD dpop_jkt VARCHAR(43) DEFAULT NULL');
        $this->addSql('ALTER TABLE beffroi_authorization_code ADD dpop_jkt VARCHAR(43) DEFAULT NULL');
        $this->addSql('ALTER TABLE beffroi_refresh_token ADD cnf JSONB DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_interaction DROP dpop_jkt');
        $this->addSql('ALTER TABLE beffroi_authorization_code DROP dpop_jkt');
        $this->addSql('ALTER TABLE beffroi_refresh_token DROP cnf');
    }
}
