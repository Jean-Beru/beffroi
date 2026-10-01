<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use function array_keys;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function sprintf;

/**
 * The seventeen columns of `heidi_user` that carry a personal datum, sealed under the data key of their
 * tenant, and the two blind indexes a search matches on (decisions 0011 and 0018).
 *
 * Every sealed column becomes unbounded binary, whatever it held: an encrypted type drops the length of
 * the column it decorates and asks the platform for a blob. `address` loses its `jsonb` with it, and with
 * that anything a query could have done with the JSON, what is in the column now being the ciphertext of
 * a JSON document.
 *
 * **The columns are recreated and their values are not carried over.** There is no deployment of this
 * provider, so there are no cleartext rows to migrate and no code to write for rows nobody has; a column
 * that would have to be read, sealed and written back is a path this repository would carry forever for a
 * case that never happens. On a table that holds rows the server refuses the migration, the username
 * coming back as a column that accepts no null.
 *
 * **The unicity of a username within a tenant moves onto the index column.** A sealed column holds a
 * different ciphertext for every write of the same username, so a unique constraint on it would refuse
 * nothing at all. No constraint is added on the address: nothing today says two users of one tenant may
 * not share one, and this is not the place that decides it.
 */
final class Version20261001180000 extends AbstractMigration
{
    /**
     * The nullable columns that carry a personal datum, by what they held before they sealed, which is
     * what `down` puts back. The one column of the seventeen that is not here is the username, which is
     * not nullable and which the index constraint hangs off.
     */
    private const array CLEARTEXT = [
        'email' => 'VARCHAR(255)',
        'phone_number' => 'VARCHAR(64)',
        'address' => 'JSONB',
        'name' => 'VARCHAR(255)',
        'given_name' => 'VARCHAR(255)',
        'family_name' => 'VARCHAR(255)',
        'middle_name' => 'VARCHAR(255)',
        'nickname' => 'VARCHAR(255)',
        'preferred_username' => 'VARCHAR(255)',
        'profile_url' => 'TEXT',
        'picture_url' => 'TEXT',
        'website_url' => 'TEXT',
        'gender' => 'VARCHAR(64)',
        'birthdate' => 'VARCHAR(10)',
        'zoneinfo' => 'VARCHAR(64)',
        'locale' => 'VARCHAR(35)',
    ];

    public function getDescription(): string
    {
        return 'The personal data of heidi_user sealed, and the blind indexes of the username and the address (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        // The constraint goes first: it is held on a column this migration drops.
        $this->addSql('DROP INDEX heidi_user_username');
        $this->addSql('ALTER TABLE heidi_user DROP username');
        $this->addSql('ALTER TABLE heidi_user ADD username BYTEA NOT NULL');

        foreach (array_keys(self::CLEARTEXT) as $column) {
            $this->addSql(sprintf('ALTER TABLE heidi_user DROP %s', $column));
            $this->addSql(sprintf('ALTER TABLE heidi_user ADD %s BYTEA DEFAULT NULL', $column));
        }

        $this->addSql('ALTER TABLE heidi_user ADD username_index VARCHAR(64) NOT NULL');
        $this->addSql('ALTER TABLE heidi_user ADD email_index VARCHAR(64) DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX heidi_user_username ON heidi_user (tenant_id, username_index)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP INDEX heidi_user_username');
        $this->addSql('ALTER TABLE heidi_user DROP username_index');
        $this->addSql('ALTER TABLE heidi_user DROP email_index');
        $this->addSql('ALTER TABLE heidi_user DROP username');
        $this->addSql('ALTER TABLE heidi_user ADD username VARCHAR(255) NOT NULL');

        foreach (self::CLEARTEXT as $column => $declaration) {
            $this->addSql(sprintf('ALTER TABLE heidi_user DROP %s', $column));
            $this->addSql(sprintf('ALTER TABLE heidi_user ADD %s %s DEFAULT NULL', $column, $declaration));
        }

        $this->addSql('CREATE UNIQUE INDEX heidi_user_username ON heidi_user (tenant_id, username)');
    }
}
