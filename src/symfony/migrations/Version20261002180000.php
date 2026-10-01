<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use function array_keys;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Heidi\Bundle\Doctrine\Migration\SealingMigration;
use function sprintf;

/**
 * The provenance of a request, sealed under the data key of its tenant, and the sentence a person reads on
 * the device that asks them to confirm (decisions 0011 and 0018).
 *
 * **Twenty columns become four.** The provenance was an embeddable of five columns, mapped four times over
 * three tables, and it could not seal: an embeddable fixes the type of each of its fields once for the
 * whole model, so the same field could not carry the type of each of the three tables that hold a
 * provenance, and the family a sealed type belongs to is its table. It is one column and one JSON document
 * now (`RequestContextType`), which is what the bundle already does with every value object a column holds
 * whole. Nothing is lost: the object is immutable and the asynchronous enrichment replaces it whole, and no
 * query anywhere read a column of a provenance on its own.
 *
 * `received_at` joins the document rather than keeping a column of its own. It says nothing of a person and
 * could have stayed in the clear, but the dates every query of these three tables uses are their own
 * (`established_at`, `last_seen_at`, `issued_at`, `expires_at`), and a column for it would be a second
 * column per provenance for nothing.
 *
 * `binding_message` seals here rather than with the other hints a request keeps, because it is this
 * migration that touches this table.
 *
 * A table that holds rows is refused before anything runs, with the sentence `SealingMigration` gives it.
 */
final class Version20261002180000 extends SealingMigration
{
    /**
     * The columns each table loses, by the one it gains. Four provenances over three tables, and the one
     * column of this migration that is not a provenance is the binding message, which the backchannel
     * table carries already and which only changes type.
     *
     * @var array<string, array<string, list<string>>> table, then the column gained, then the ones lost
     */
    private const array PROVENANCES = [
        'heidi_authentication_session' => [
            'created_from' => [
                'created_from_received_at',
                'created_from_ip_address',
                'created_from_user_agent',
                'created_from_location',
                'created_from_device',
            ],
            'last_seen_from' => [
                'last_seen_from_received_at',
                'last_seen_from_ip_address',
                'last_seen_from_user_agent',
                'last_seen_from_location',
                'last_seen_from_device',
            ],
        ],
        'heidi_device_authorization_request' => [
            'requested_from' => [
                'requested_from_received_at',
                'requested_from_ip_address',
                'requested_from_user_agent',
                'requested_from_location',
                'requested_from_device',
            ],
        ],
        'heidi_backchannel_authentication_request' => [
            'requested_from' => [
                'requested_from_received_at',
                'requested_from_ip_address',
                'requested_from_user_agent',
                'requested_from_location',
                'requested_from_device',
            ],
        ],
    ];

    /**
     * What each column of a provenance held before it became one document, which is what `down` puts back.
     *
     * @var array<string, string> the suffix of the column, then its declaration
     */
    private const array CLEARTEXT = [
        'received_at' => 'TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL',
        'ip_address' => 'VARCHAR(45) DEFAULT NULL',
        'user_agent' => 'VARCHAR(1024) DEFAULT NULL',
        'location' => 'JSONB DEFAULT NULL',
        'device' => 'JSONB DEFAULT NULL',
    ];

    /**
     * @return list<string>
     */
    protected function tablesToSeal(): array
    {
        return array_keys(self::PROVENANCES);
    }

    public function getDescription(): string
    {
        return 'The provenance of a request as one sealed column, and the binding message of a backchannel request (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::PROVENANCES as $table => $provenances) {
            foreach ($provenances as $column => $lost) {
                foreach ($lost as $old) {
                    $this->addSql(sprintf('ALTER TABLE %s DROP %s', $table, $old));
                }
                $this->addSql(sprintf('ALTER TABLE %s ADD %s BYTEA NOT NULL', $table, $column));
            }
        }

        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request DROP binding_message');
        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request ADD binding_message BYTEA DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request DROP binding_message');
        $this->addSql('ALTER TABLE heidi_backchannel_authentication_request ADD binding_message VARCHAR(255) DEFAULT NULL');

        foreach (self::PROVENANCES as $table => $provenances) {
            foreach (array_keys($provenances) as $column) {
                $this->addSql(sprintf('ALTER TABLE %s DROP %s', $table, $column));
                foreach (self::CLEARTEXT as $suffix => $declaration) {
                    $this->addSql(sprintf('ALTER TABLE %s ADD %s_%s %s', $table, $column, $suffix, $declaration));
                }
            }
        }
    }
}
