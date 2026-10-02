<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a backchannel authentication request asks the authentication of its user to reach (CIBA Core
 * §7.1): the classes the client named, in its order of preference, kept on the record so that the page
 * where that user answers can ask for one more proof before recording the approval (decision 0010). The
 * column is the JSON of the wire, as "acr_values" is on the request an interaction parked.
 *
 * The rows the table already holds asked for no class, and such a request lives minutes, so they are
 * deleted and the column is mandatory from the start rather than nullable for ever: a client whose
 * request goes with them starts another one, which is what it does when one expires.
 */
final class Version20260927140000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The classes a backchannel authentication request asks its user to prove.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DELETE FROM beffroi_backchannel_authentication_request');
        $this->addSql('ALTER TABLE beffroi_backchannel_authentication_request ADD acr_values JSONB NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE beffroi_backchannel_authentication_request DROP acr_values');
    }
}
