<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\CountingKms;
use Beffroi\Core\Domain\Identity\EmailAddress;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ServicesResetter;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;

final class DataKeyStoreTest extends DatabaseTestCase
{
    private const string TABLE = 'test_sealed_column';

    private const string FAMILY = 'user';

    protected function setUp(): void
    {
        parent::setUp();
        self::connection()->executeStatement('CREATE TABLE ' . self::TABLE . ' (id INTEGER PRIMARY KEY, value BLOB)');
        self::kms()->forget();
    }

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
     * Decision 0018
     */
    #[Test]
    public function aValueSealedThenReadInOneProcessCostsOneCallToTheKms(): void
    {
        // Given
        self::seal(1, 'alice@example.com');

        // When
        self::read(1);

        // Then
        static::assertSame(1, self::kms()->minted);
        static::assertSame(0, self::kms()->unwrapped);
    }

    /**
     * Decision 0018
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
        $read = self::typesOfTheConnection()
            ->get(EncryptedColumnTypes::name(self::FAMILY, 'beffroi_email_address'))
            ->convertToPHPValue(
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
