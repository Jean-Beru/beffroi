<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * The wrapped data keys of every tenant, one per tenant and per family of columns (decisions 0011 and
 * 0018): what every sealed column of a personal datum refers to by a reference of sixteen bytes, instead
 * of carrying the wrapped key itself.
 *
 * Five columns and nothing else, which is the whole of what the store of the bridge names. The identifier
 * is a UUIDv7, which sorts chronologically, so the newest key of a scope is what `ORDER BY id DESC` gives
 * and the index on the scope and the identifier is what makes that one row a lookup. The key material is
 * the data key as its master key wrapped it, never in the clear. The master key and the client are written
 * on the row rather than read from the configuration, which is what makes a read resolve whatever wrote
 * it: changing master key or backend rewraps these rows and reads no encrypted value at all
 * (`key-management:rewrap-data-keys`).
 *
 * A retired key is never deleted, its rows keeping their reference to it: what it sealed stays readable,
 * and a key retires so that no single key seals more values than the 96-bit nonce of AES-256-GCM allows
 * (NIST SP 800-38D).
 *
 * The table carries no tenant column. The scope does, as the slug the encrypter of the bundle prefixes the
 * family with, because a scope is the only channel between an encrypted type and this store.
 */
final class Version20261001120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'The wrapped data key of a tenant and of a family of columns (decisions 0011 and 0018).';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('CREATE TABLE beffroi_data_key (id BYTEA NOT NULL, scope VARCHAR(191) NOT NULL, key_material BYTEA NOT NULL, master_key_id VARCHAR(255) NOT NULL, client VARCHAR(64) NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX beffroi_data_key_scope_idx ON beffroi_data_key (scope, id)');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(! $this->platform instanceof PostgreSQLPlatform, 'This migration is written for PostgreSQL.');

        $this->addSql('DROP TABLE beffroi_data_key');
    }
}
