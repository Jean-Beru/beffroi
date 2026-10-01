<?php

declare(strict_types=1);

namespace Heidi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Heidi\Bundle\Doctrine\Migration\SealingMigration;
use function sprintf;

/**
 * What a client registered of the people responsible for it, and the secret this provider handed it,
 * sealed under the data key of their tenant (decisions 0011 and 0018). The last family of columns this
 * spike seals.
 *
 * **Three columns of one table, and no index.** A client is found by `client_id`, unique under its tenant
 * and in the clear, and nothing looks a client up by a member of its metadata.
 *
 * The three lose their `jsonb` with the rest, what each holds now being the ciphertext of a JSON document.
 * `assigned_metadata` loses its default too, and that is a stronger case of the same rule: `jsonb` only
 * took a query away, where `BYTEA DEFAULT '{}'` would put two bytes in the column that no key opens, and a
 * row inserted without that column would hold something that is not a ciphertext.
 *
 * **The secret is the one column of this schema that is neither a personal datum nor safe in the clear**
 * (RFC 7591 §3.2.1): a digest for a method that receives a secret, which would need nothing, or the secret
 * itself for `client_secret_jwt`, which signs with it and cannot hash it (OIDC Core §9). A credential that
 * cannot be hashed is sealed instead, so a dump of the database yields no usable client credential either.
 *
 * The columns are recreated rather than converted, as every sealed column of this spike was: there is no
 * deployment, so there are no cleartext rows worth a conversion path. A table that holds rows is refused
 * before anything runs, with the sentence `SealingMigration` gives it, and this table holds the clients a
 * provisioning run and the demonstration walks registered: on a development stack they are registered
 * again.
 */
final class Version20261004120000 extends SealingMigration
{
    private const string TABLE = 'heidi_client';

    /**
     * What each column held before it sealed and what it is once it seals, which is what `down` and `up`
     * put back: as nullable as it was, sealing a column changing nothing of what the domain requires of
     * it, and with nothing defaulted.
     *
     * @var array<string, array{string, string}> column, then its sealed declaration and its cleartext one
     */
    private const array COLUMNS = [
        'metadata' => ['BYTEA NOT NULL', 'JSONB NOT NULL'],
        'assigned_metadata' => ['BYTEA NOT NULL', "JSONB DEFAULT '{}' NOT NULL"],
        'secret' => ['BYTEA DEFAULT NULL', 'JSONB DEFAULT NULL'],
    ];

    /**
     * @return list<string>
     */
    protected function tablesToSeal(): array
    {
        return [self::TABLE];
    }

    public function getDescription(): string
    {
        return 'The registered metadata, the assigned metadata and the secret of a client, sealed (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::COLUMNS as $column => [$sealed]) {
            $this->addSql(sprintf('ALTER TABLE %s DROP %s', self::TABLE, $column));
            $this->addSql(sprintf('ALTER TABLE %s ADD %s %s', self::TABLE, $column, $sealed));
        }
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        foreach (self::COLUMNS as $column => [, $cleartext]) {
            $this->addSql(sprintf('ALTER TABLE %s DROP %s', self::TABLE, $column));
            $this->addSql(sprintf('ALTER TABLE %s ADD %s %s', self::TABLE, $column, $cleartext));
        }
    }
}
