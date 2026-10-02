<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The "acr" policy of the tenant (decision 0010, architecture §3.1, §5.3), generated from the XML mapping
 * against PostgreSQL 16 and kept equal to it by a test. The default of the column is the default policy,
 * so that the tenant of a deployment of spike 2 keeps the vocabulary it had.
 */
final class Version20260920120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The authentication context policy of the tenant.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_tenant ADD authentication_context_policy JSON DEFAULT \'{"classes":[{"name":"phrh","predicate":"phishing_resistant_hardware"},{"name":"phr","predicate":"phishing_resistant"},{"name":"2","predicate":"two_factors"},{"name":"1","predicate":"single_factor"}]}\' NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_tenant DROP authentication_context_policy');
    }
}
