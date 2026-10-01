<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use function array_keys;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Heidi\Bundle\Doctrine\Migration\SealingMigration;
use function sprintf;

/**
 * What a request keeps of the person it asks for, sealed under the data key of its tenant (decisions 0011
 * and 0018): the two hints a client may send, and the parameters of a request it pushed.
 *
 * **Three columns over two tables, and no index.** Nothing looks a row up by a hint: an interaction is
 * found by its identifier, and a pushed request by the digest of the reference it was answered with, which
 * is its primary key and stays in the clear.
 *
 * The two hints are columns of `heidi_interaction` because the request is an embeddable that one entity
 * embeds, with no column prefix. `parameters` loses its `jsonb` with the rest, what the column holds now
 * being the ciphertext of a JSON document; it keeps the hints word for word as the client wrote them
 * (RFC 9126 §2.2), which is the whole reason it seals.
 *
 * The columns are recreated rather than converted, as every sealed column of this spike was: there is no
 * deployment, so there are no cleartext rows worth a conversion path. A table that holds rows is refused
 * before anything runs, with the sentence `SealingMigration` gives it, and these two tables hold rows that
 * live minutes: a run that refuses is a run started while a login was in flight.
 */
final class Version20261003180000 extends SealingMigration
{
    /**
     * What each column held before it sealed, by the table that holds it, which is what `down` puts back.
     *
     * @var array<string, array<string, string>> table, then column, then its declaration
     */
    private const array CLEARTEXT = [
        'heidi_interaction' => [
            'login_hint' => 'TEXT DEFAULT NULL',
            'id_token_hint' => 'TEXT DEFAULT NULL',
        ],
        'heidi_pushed_authorization_request' => [
            'parameters' => 'JSONB NOT NULL',
        ],
    ];

    /**
     * What each column is once it seals: binary, and as nullable as it was, sealing a column changing
     * nothing of what the domain requires of it.
     *
     * @var array<string, string>
     */
    private const array SEALED = [
        'login_hint' => 'BYTEA DEFAULT NULL',
        'id_token_hint' => 'BYTEA DEFAULT NULL',
        'parameters' => 'BYTEA NOT NULL',
    ];

    /**
     * @return list<string>
     */
    protected function tablesToSeal(): array
    {
        return array_keys(self::CLEARTEXT);
    }

    public function getDescription(): string
    {
        return 'The two hints of a request and the parameters of a pushed one, sealed (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::CLEARTEXT as $table => $columns) {
            foreach (array_keys($columns) as $column) {
                $this->addSql(sprintf('ALTER TABLE %s DROP %s', $table, $column));
                $this->addSql(sprintf('ALTER TABLE %s ADD %s %s', $table, $column, self::SEALED[$column]));
            }
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::CLEARTEXT as $table => $columns) {
            foreach ($columns as $column => $declaration) {
                $this->addSql(sprintf('ALTER TABLE %s DROP %s', $table, $column));
                $this->addSql(sprintf('ALTER TABLE %s ADD %s %s', $table, $column, $declaration));
            }
        }
    }
}
