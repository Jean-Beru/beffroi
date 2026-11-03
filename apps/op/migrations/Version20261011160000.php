<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The floor of every login of a tenant (issue #327): one column on the tenant, naming a predicate of the
 * provider (decision 0010).
 *
 * The single factor on every row written before this, which is the predicate every login of this provider
 * satisfies: a tenant that has not hardened signs its users in exactly as it did. What raising the floor
 * does to the credentials it then forbids is an act of administration and not a migration (TenantHardening),
 * so nothing here revokes anything.
 */
final class Version20261011160000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The floor of every login of a tenant (issue #327).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql("ALTER TABLE beffroi_tenant ADD login_floor VARCHAR(32) DEFAULT 'single_factor' NOT NULL");
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_tenant DROP login_floor');
    }
}
