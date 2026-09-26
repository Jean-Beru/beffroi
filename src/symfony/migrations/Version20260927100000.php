<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * What a request asks for beyond its scopes (RFC 9396 §2): a scope says what kind of thing a client may do,
 * an "authorization_details" says what it may do, to what and how much, so it travels exactly where a scope
 * list travels. The request the interaction parked carries it, the consent the user gave carries what they
 * agreed to, the code carries what the tokens will descend from, and the refresh token and the opaque access
 * token carry what they are good for.
 *
 * The array is stored in the JSON of the wire, which is the same array a token carries and an introspection
 * renders (§7, §9): nothing is rewritten between what was agreed to and what a resource server reads.
 */
final class Version20260927100000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'What a request asks for beyond its scopes, carried by the interaction, the consent, the code and the tokens.';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_interaction ADD authorization_details JSONB DEFAULT NULL');
        $this->addSql('ALTER TABLE heidi_consent ADD authorization_details JSONB DEFAULT NULL');
        $this->addSql('ALTER TABLE heidi_authorization_code ADD authorization_details JSONB DEFAULT NULL');
        $this->addSql('ALTER TABLE heidi_refresh_token ADD authorization_details JSONB DEFAULT NULL');
        $this->addSql('ALTER TABLE heidi_access_token ADD authorization_details JSONB DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_interaction DROP authorization_details');
        $this->addSql('ALTER TABLE heidi_consent DROP authorization_details');
        $this->addSql('ALTER TABLE heidi_authorization_code DROP authorization_details');
        $this->addSql('ALTER TABLE heidi_refresh_token DROP authorization_details');
        $this->addSql('ALTER TABLE heidi_access_token DROP authorization_details');
    }
}
