<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Type;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\CountingKms;
use Beffroi\Core\Domain\Identity\EmailAddress;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ServicesResetter;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;

/**
 * Decisions 0011 and 0018, wired: a data key per tenant and per family of columns, wrapped by the master
 * key of that tenant, held in a table of this provider, and a KMS asked once per key and per process rather
 * than once per value.
 *
 * What is played here is the whole chain the deployment has, and not a piece of it: a registered encrypted
 * type, the encrypter that composes the scope with the ambient tenant, the router that sends a write to
 * the store of that tenant, the store, and the table. The tenant is the one the configuration of this
 * kernel names, there being one; a second tenant and a unit of work with none are what the unit test of
 * the encrypter shows, no configuration of one tenant being able to.
 */
final class DataKeyStoreTest extends DatabaseTestCase
{
    /**
     * A table of this test alone: no mapping of the provider names an encrypted type yet, and what a sealed
     * column holds is what the assertions below read.
     */
    private const string TABLE = 'test_sealed_column';

    private const string FAMILY = 'user';

    protected function setUp(): void
    {
        parent::setUp();
        self::connection()->executeStatement('CREATE TABLE ' . self::TABLE . ' (id INTEGER PRIMARY KEY, value BLOB)');
        self::kms()->forget();
    }

    /**
     * The scope of the row is the family prefixed by the slug of the tenant, which is the only channel
     * there is between an encrypted type and the store: the store returns the newest key of a scope and
     * reads no other column, so what is not in the scope is not in the routing.
     */
    #[Test]
    public function sealingAColumnWritesOneDataKeyForTheTenantAndTheFamily(): void
    {
        // When
        self::seal(1, 'alice@example.com');

        // Then
        $rows = self::dataKeys();
        static::assertCount(1, $rows);
        static::assertSame(TenantScopedEncrypter::scope(self::tenant()->slug, self::FAMILY), $rows[0]['scope']);
    }

    /**
     * The third success criterion of the spike: the KMS is not in the path of every row. One data key is
     * minted for the family, and the values that follow are sealed under the key the process already
     * holds.
     */
    #[Test]
    public function tenValuesOfOneFamilyCostOneCallToTheKms(): void
    {
        // When
        for ($id = 1; $id <= 10; ++$id) {
            self::seal($id, 'alice' . $id . '@example.com');
        }

        // Then
        static::assertSame(1, self::kms()->minted);
        static::assertSame(0, self::kms()->unwrapped);
        static::assertCount(1, self::dataKeys());
    }

    /**
     * A second process pays one unwrap for the data key it did not mint, and nothing per value: what it
     * reads back refers to a key by a reference of sixteen bytes, and the key is what the KMS opens once.
     */
    #[Test]
    public function aSecondProcessPaysOneUnwrapForTheKeyAndNoneForTheValues(): void
    {
        // Given
        for ($id = 1; $id <= 5; ++$id) {
            self::seal($id, 'alice' . $id . '@example.com');
        }

        // When
        self::ensureKernelShutdown();
        self::bootKernel();
        self::kms()->forget();
        $read = [];
        for ($id = 1; $id <= 5; ++$id) {
            $read[] = self::read($id);
        }

        // Then
        static::assertSame(['alice1@example.com', 'alice2@example.com', 'alice3@example.com', 'alice4@example.com', 'alice5@example.com'], $read);
        static::assertSame(1, self::kms()->unwrapped);
        static::assertSame(0, self::kms()->minted);
    }

    /**
     * Decision 0018: the stores of this provider do not carry "kernel.reset". The component tags its own
     * store with it, and "forget()" releases every retained plaintext between two units of work, which
     * under FrankenPHP in worker mode would put the KMS back on the path of every request that touches a
     * column. A thread keeps open what it has opened, as it already keeps an open signing key, so the
     * reset every unit of work goes through leaves the data key where it is.
     */
    #[Test]
    public function aResetBetweenTwoUnitsOfWorkDoesNotGiveBackTheDataKey(): void
    {
        // Given
        self::seal(1, 'alice@example.com');

        // When
        self::service('services_resetter', ServicesResetter::class)->reset();
        self::seal(2, 'bob@example.com');

        // Then
        static::assertSame(1, self::kms()->minted);
        static::assertSame(0, self::kms()->unwrapped);
        static::assertCount(1, self::dataKeys());
    }

    /**
     * The row carries the client and the master key that wrapped it, so a read resolves whatever wrote it
     * and the router sends no read anywhere: that is what keeps one reader in front of every reference.
     */
    #[Test]
    public function theRowNamesTheClientAndTheMasterKeyThatWrappedIt(): void
    {
        // When
        self::seal(1, 'alice@example.com');

        // Then
        $rows = self::dataKeys();
        static::assertSame('test', $rows[0]['client']);
        static::assertNotSame('', $rows[0]['master_key_id']);
    }

    /**
     * The one store every read goes to is also what declares the table in the schema the ORM assembles,
     * which is what keeps "doctrine:schema:update" from offering to drop it.
     */
    #[Test]
    public function theReaderOfTheRouterIsAStoreOfTheBridge(): void
    {
        // When / Then
        static::assertInstanceOf(DataKeyStore::class, self::service('beffroi.data_keys.reader', DataKeyStore::class));
    }

    private static function seal(int $id, string $address): void
    {
        self::connection()
            ->insert(
                self::TABLE,
                [
                    'id' => $id,
                    'value' => new EmailAddress($address),
                ],
                [
                    'value' => EncryptedColumnTypes::name(self::FAMILY, 'beffroi_email_address'),
                ],
            );
    }

    private static function read(int $id): string
    {
        $stored = self::connection()->fetchOne('SELECT value FROM ' . self::TABLE . ' WHERE id = ?', [$id]);
        static::assertIsString($stored);
        $read = Type::getTypeRegistry()->get(EncryptedColumnTypes::name(self::FAMILY, 'beffroi_email_address'))->convertToPHPValue(
            $stored,
            self::connection()->getDatabasePlatform(),
        );
        static::assertInstanceOf(EmailAddress::class, $read);

        return $read->value;
    }

    /**
     * @return list<array{scope: string, master_key_id: string, client: string}>
     */
    private static function dataKeys(): array
    {
        $rows = [];
        foreach (self::connection()->iterateAssociative('SELECT scope, master_key_id, client FROM beffroi_data_key ORDER BY id') as $row) {
            static::assertIsString($row['scope']);
            static::assertIsString($row['master_key_id']);
            static::assertIsString($row['client']);
            $rows[] = [
                'scope' => $row['scope'],
                'master_key_id' => $row['master_key_id'],
                'client' => $row['client'],
            ];
        }

        return $rows;
    }

    private static function kms(): CountingKms
    {
        return self::service(CountingKms::class, CountingKms::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
