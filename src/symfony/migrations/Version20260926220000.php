<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The grant a device authorization request and a backchannel authentication request name, and the instant
 * it was revoked (architecture §4.6). Both flows issue tokens without writing an authorization code, and a
 * resource of this provider asks of every token whether the grant behind it is still alive: the answer is
 * a row of the table the flow writes, under a unique constraint, as it is for a code.
 *
 * The rows the two tables already hold name no grant, and the tokens of those requests are exactly the
 * ones no resource of this provider could answer for. Both records live minutes, so they are deleted and
 * the column is mandatory from the start rather than nullable for ever: a client whose request goes with
 * them starts another one, which is what it does when one expires.
 */
final class Version20260926220000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The grant a device authorization request and a backchannel authentication request name.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DELETE FROM heidi_device_authorization_request');
        $this->addSql('ALTER TABLE heidi_device_authorization_request ADD grant_id UUID NOT NULL');
        $this->addSql('ALTER TABLE heidi_device_authorization_request ADD revoked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX heidi_device_authorization_grant ON heidi_device_authorization_request (grant_id)');

        $this->addSql('DELETE FROM heidi_backchannel_authentication_request');
        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request ADD grant_id UUID NOT NULL');
        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request ADD revoked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX heidi_backchannel_authentication_grant ON heidi_backchannel_authentication_request (grant_id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP INDEX heidi_backchannel_authentication_grant');
        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request DROP revoked_at');
        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request DROP grant_id');
        $this->addSql('DROP INDEX heidi_device_authorization_grant');
        $this->addSql('ALTER TABLE heidi_device_authorization_request DROP revoked_at');
        $this->addSql('ALTER TABLE heidi_device_authorization_request DROP grant_id');
    }
}
