<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctrine\PersonalData;

use App\Doctrine\PersonalData\TenantDataKeyStores;
use App\Doctrine\PersonalData\TenantScopedDataKeyStore;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Closure;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;
use Symfony\Component\KeyManagement\Command\RewrapDataKeysCommand;
use Symfony\Component\KeyManagement\DataKeyHandle;
use Symfony\Component\KeyManagement\Exception\DataKeyNotFoundException;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;
use Symfony\Component\KeyManagement\Exception\RuntimeException;
use Symfony\Component\KeyManagement\StoredDataKey;
use Symfony\Component\KeyManagement\Test\InMemoryKms;
use Symfony\Component\KeyManagement\Test\SwitchableKms;
use Symfony\Component\Uid\UuidV7;

final class TenantDataKeyStoresTest extends TestCase
{
    private const string SCOPE = 'acme.user';

    private const string MASTER_KEY = 'beffroi-{tenant}';

    private Connection $connection;

    private SwitchableKms $kms;

    /**
     * @var ServiceLocator<SwitchableKms>
     */
    private ServiceLocator $clients;

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ]);
        $kms = new SwitchableKms(new InMemoryKms('op'), new RuntimeException('Failed to reach the KMS.'));
        $this->kms = $kms;
        $this->clients = new ServiceLocator([
            'op' => static fn (): SwitchableKms => $kms,
        ]);
        $this->stores(['current'])->reader()->createTable();
    }

    #[Test]
    public function aRowBoundUnderASecretNoLongerListedOpensNothing(): void
    {
        // Given
        $reference = $this->stores(['retired'])->current(self::SCOPE)->reference;

        // Then
        $this->expectException(DecryptionFailedException::class);

        // When
        $this->stores(['current'])->get($reference);
    }

    #[Test]
    public function aRowBoundUnderASecretListedSecondStillOpens(): void
    {
        // Given
        $reference = $this->stores(['retired'])->current(self::SCOPE)->reference;

        // When
        $handle = $this->stores(['current', 'retired'])->get($reference);

        // Then
        static::assertSame($reference, $handle->reference);
    }

    #[Test]
    public function aRewrapBindsTheRowsAgainUnderTheFirstSecret(): void
    {
        // Given
        $reference = $this->stores(['retired'])->current(self::SCOPE)->reference;
        new RewrapDataKeysCommand(new TenantScopedDataKeyStore($this->stores(['current', 'retired']), Fixtures::tenant('acme')), $this->clients)->__invoke(
            new SymfonyStyle(new ArrayInput([]), new BufferedOutput()),
            to: 'op',
            keyId: 'beffroi-acme',
        );

        // When
        $handle = $this->stores(['current'])->get($reference);

        // Then
        static::assertSame($reference, $handle->reference);
    }

    #[Test]
    public function theKmsOpensADataKeyUnderTheContextOfItsReferenceAndItsScope(): void
    {
        // Given
        $minted = $this->stores(['current'])->current(self::SCOPE)->use(static fn (string $key): string => $key);
        $row = $this->row();

        // When
        $unwrapped = $this->kms->unwrapDataKey($row->wrapped, StoredDataKey::wrappingContextFor($row->reference, $row->scope));

        // Then
        static::assertSame($minted, $unwrapped->use(static fn (string $key): string => $key));
    }

    /**
     * @param Closure(StoredDataKey): string $context
     */
    #[Test]
    #[DataProvider('provideAnotherContext')]
    public function theKmsRefusesADataKeyPresentedUnderAnotherContext(Closure $context): void
    {
        // Given
        $this->stores(['current'])->current(self::SCOPE);
        $row = $this->row();

        // Then
        $this->expectException(DecryptionFailedException::class);

        // When
        $this->kms->unwrapDataKey($row->wrapped, $context($row));
    }

    /**
     * @return iterable<string, array{Closure(StoredDataKey): string}>
     */
    public static function provideAnotherContext(): iterable
    {
        yield 'none' => [static fn (StoredDataKey $row): string => ''];
        yield 'the context of another scope' => [
            static fn (StoredDataKey $row): string => StoredDataKey::wrappingContextFor($row->reference, 'acme.journal'),
        ];
        yield 'the context of another reference' => [
            static fn (StoredDataKey $row): string => StoredDataKey::wrappingContextFor(new UuidV7()->toBinary(), $row->scope),
        ];
    }

    #[Test]
    public function aDataKeyWrappedUnderNoContextOpensNothing(): void
    {
        // Given
        $reference = new DataKeyStore(
            $this->connection,
            $this->clients,
            'op',
            'beffroi-acme',
            ['current'],
            TenantDataKeyStores::TABLE,
        )->current(self::SCOPE)->reference;

        // Then
        $this->expectException(DecryptionFailedException::class);

        // When
        $this->stores(['current'])->get($reference);
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function aKeyMintedToSealIsTheKeyAReadFindsOpen(): void
    {
        // Given
        $stores = $this->stores(['current']);
        $reference = $stores->current(self::SCOPE)->reference;

        // When
        $stores->get($reference);

        // Then
        static::assertSame(0, $this->kms->calls['unwrapDataKey'] ?? 0);
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function aKeyOpenedToReadIsTheKeyASealFindsOpen(): void
    {
        // Given
        $reference = $this->stores(['current'])->current(self::SCOPE)->reference;
        $stores = $this->stores(['current']);
        $stores->get($reference);

        // When
        $stores->current(self::SCOPE);

        // Then
        static::assertSame(1, $this->kms->calls['unwrapDataKey'] ?? 0);
    }

    #[Test]
    public function aKeyAlreadyOpenedIsAnsweredWithoutReadingItsRowAgain(): void
    {
        // Given
        $reference = $this->stores(['current'])->current(self::SCOPE)->reference;
        $stores = $this->stores(['current']);
        $stores->get($reference);
        $this->connection->executeStatement('DELETE FROM ' . TenantDataKeyStores::TABLE);

        // When
        $handle = $stores->get($reference);

        // Then
        static::assertSame($reference, $handle->reference);
    }

    #[Test]
    public function aReferenceThatNamesNoRowIsNoDataKey(): void
    {
        // Then
        $this->expectException(DataKeyNotFoundException::class);

        // When
        $this->stores(['current'])->get(new UuidV7()->toBinary());
    }

    /**
     * Decision 0018
     *
     * @param Closure(TenantDataKeyStores, string): DataKeyHandle $ask
     */
    #[Test]
    #[DataProvider('provideWhatAsksTheKms')]
    public function aKmsThatDoesNotAnswerIsAnOutage(Closure $ask, string $message): void
    {
        // Given
        $reference = $this->stores(['current'])->current(self::SCOPE)->reference;
        $this->kms->down = true;

        // When
        try {
            $ask($this->stores(['current']), $reference);
            static::fail('The KMS was asked nothing.');
        } catch (KmsUnavailableException $outage) {
            // Then
            static::assertSame($message, $outage->getMessage());
            static::assertSame('Failed to reach the KMS.', $outage->getPrevious()?->getMessage());
        }
    }

    /**
     * @return iterable<string, array{Closure(TenantDataKeyStores, string): DataKeyHandle, string}>
     */
    public static function provideWhatAsksTheKms(): iterable
    {
        yield 'a key opened by its reference' => [
            static fn (TenantDataKeyStores $stores, string $reference): DataKeyHandle => $stores->get($reference),
            'The data key of a sealed value could not be opened.',
        ];
        yield 'the current key of a scope, opened' => [
            static fn (TenantDataKeyStores $stores): DataKeyHandle => $stores->current(self::SCOPE),
            'The data key of the scope "acme.user" could not be opened or minted.',
        ];
        yield 'the first key of a scope, minted' => [
            static fn (TenantDataKeyStores $stores): DataKeyHandle => $stores->current('acme.journal'),
            'The data key of the scope "acme.journal" could not be opened or minted.',
        ];
        yield 'a key minted in place of the current one' => [
            static fn (TenantDataKeyStores $stores): DataKeyHandle => $stores->rotate(self::SCOPE),
            'No new data key could be minted for the scope "acme.user".',
        ];
    }

    /**
     * @param non-empty-list<string> $secrets
     */
    private function stores(array $secrets): TenantDataKeyStores
    {
        return new TenantDataKeyStores($this->connection, $this->clients, 'op', self::MASTER_KEY, $secrets, TenantDataKeyStores::TABLE);
    }

    private function row(): StoredDataKey
    {
        return [...$this->stores(['current'])->all()][0] ?? static::fail('The store holds no data key.');
    }
}
