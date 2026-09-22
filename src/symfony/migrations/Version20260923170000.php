<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a pushed authorization request was carried by. A client held to signing its requests
 * (OIDC Registration, require_signed_request_object) pushes the object to the endpoint that verifies it,
 * and the authorization endpoint then reads a record and no longer the object; the record says whether
 * there was one, so that the requirement is judged where the request actually starts.
 */
final class Version20260923170000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Whether a pushed authorization request was carried by a signed request object.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_pushed_authorization_request ADD carried_by_signed_object BOOLEAN NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_pushed_authorization_request DROP carried_by_signed_object');
    }
}
