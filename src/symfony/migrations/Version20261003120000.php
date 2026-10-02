<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use function array_keys;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Beffroi\Bundle\Doctrine\Migration\SealingMigration;
use function sprintf;

/**
 * The name a person gave a passkey, and what a push subscription holds of one of their devices, sealed
 * under the data key of their tenant (decisions 0011 and 0018).
 *
 * Three columns over two tables, and nothing else: no index, no constraint moved, no lookup changed.
 *
 * **Neither table needs a blind index, for a different reason each.** What a ceremony finds a passkey by
 * is its credential ID and its user handle, both of which stay in the clear, being published by the
 * authenticator and drawn at random; nobody searches a passkey by the name its owner typed. And
 * `beffroi_push_subscription` already holds the digest of its endpoint in a column of its own, with the
 * unique constraint and the lookup on it, which is the shape a blind index would have had to build: it was
 * built there for its own reason, an endpoint being longer than a key may be, and sealing the endpoint
 * takes nothing away from it.
 *
 * The columns are recreated rather than converted, as every sealed column of this spike was: there is no
 * deployment, so there are no cleartext rows worth a conversion path. A table that holds rows is refused
 * before anything runs, with the sentence `SealingMigration` gives it.
 */
final class Version20261003120000 extends SealingMigration
{
    /**
     * What each column held before it sealed, by the table that holds it, which is what `down` puts back.
     * The two that are not nullable are not nullable afterwards either: a passkey has a name and a
     * subscription has an endpoint, and sealing a column does not change what the domain requires of it.
     *
     * @var array<string, array<string, array{string, bool}>> table, then column, then its declaration and
     *                                                        whether it accepts a null
     */
    private const array CLEARTEXT = [
        'beffroi_passkey_credential' => [
            'name' => ['VARCHAR(255)', false],
        ],
        'beffroi_push_subscription' => [
            'endpoint' => ['TEXT', false],
            'label' => ['VARCHAR(255)', true],
        ],
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
        return 'The name of a passkey, and the endpoint and the label of a push subscription, sealed (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::CLEARTEXT as $table => $columns) {
            foreach ($columns as $column => [, $nullable]) {
                $this->addSql(sprintf('ALTER TABLE %s DROP %s', $table, $column));
                $this->addSql(sprintf('ALTER TABLE %s ADD %s BYTEA %s', $table, $column, $nullable ? 'DEFAULT NULL' : 'NOT NULL'));
            }
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::CLEARTEXT as $table => $columns) {
            foreach ($columns as $column => [$declaration, $nullable]) {
                $this->addSql(sprintf('ALTER TABLE %s DROP %s', $table, $column));
                $this->addSql(sprintf(
                    'ALTER TABLE %s ADD %s %s %s',
                    $table,
                    $column,
                    $declaration,
                    $nullable ? 'DEFAULT NULL' : 'NOT NULL',
                ));
            }
        }
    }
}
