<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The resources a request asked its tokens for (RFC 8707 §2). They are named at the authorization
 * endpoint, travel with the interaction, the code and the refresh token, and are what the access token
 * is addressed to; a row that names none is a request that named none, whose token is addressed to its
 * own client.
 */
final class Version20260925120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The resources an authorization was asked for.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_interaction ADD resources TEXT DEFAULT NULL');
        $this->addSql('ALTER TABLE beffroi_authorization_code ADD resources TEXT DEFAULT NULL');
        $this->addSql('ALTER TABLE beffroi_access_token ADD resources TEXT DEFAULT NULL');
        $this->addSql('ALTER TABLE beffroi_refresh_token ADD resources TEXT DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_interaction DROP resources');
        $this->addSql('ALTER TABLE beffroi_authorization_code DROP resources');
        $this->addSql('ALTER TABLE beffroi_access_token DROP resources');
        $this->addSql('ALTER TABLE beffroi_refresh_token DROP resources');
    }
}
