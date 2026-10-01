<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The three columns of `heidi_linked_identity` sealed under the data key of their tenant, and the blind
 * index of the pair a federated login recognises an identity by (decisions 0011 and 0018).
 *
 * **The table is sealed before a federation fills it, and that is why it is sealed now.** What writes a row
 * today is `heidi:user:link`, by hand or from a provisioning run, and what reads one is the grant that
 * reads an assertion of a trusted issuer: one row per identity, where a federation writes one per person
 * who signs in through it. A blind index added once a directory has been imported is a reindex, which
 * means reading and unsealing every row of every tenant of a customer; added here it is this migration and
 * nothing else, so the spike that federates has nothing to migrate and nothing to add.
 *
 * The columns are recreated rather than converted, as the columns of `heidi_user` were and for the same
 * reason: there is no deployment, so there are no cleartext rows worth a conversion path. On a table that
 * holds rows the server refuses the migration, the three columns coming back as columns that accept no
 * null. `claims` loses its `jsonb` with the rest, what the column holds being the ciphertext of a JSON
 * document.
 *
 * **The unique constraint moves onto the two index columns.** A sealed column holds a different ciphertext
 * for every write of the same value, so the constraint on the pair in the clear would refuse nothing.
 */
final class Version20261002120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The provider, the subject and the claims of heidi_linked_identity sealed, and the blind index of the pair (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        // The constraint goes first: it is held on two columns this migration drops.
        $this->addSql('DROP INDEX heidi_linked_identity_subject');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP provider');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP subject');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP claims');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD provider BYTEA NOT NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD provider_index VARCHAR(64) NOT NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD subject BYTEA NOT NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD subject_index VARCHAR(64) NOT NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD claims BYTEA NOT NULL');
        $this->addSql('CREATE UNIQUE INDEX heidi_linked_identity_subject ON heidi_linked_identity (tenant_id, provider_index, subject_index)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP INDEX heidi_linked_identity_subject');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP provider_index');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP subject_index');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP provider');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP subject');
        $this->addSql('ALTER TABLE heidi_linked_identity DROP claims');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD provider VARCHAR(255) NOT NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD subject VARCHAR(255) NOT NULL');
        $this->addSql('ALTER TABLE heidi_linked_identity ADD claims JSONB NOT NULL');
        $this->addSql('CREATE UNIQUE INDEX heidi_linked_identity_subject ON heidi_linked_identity (tenant_id, provider, subject)');
    }
}
