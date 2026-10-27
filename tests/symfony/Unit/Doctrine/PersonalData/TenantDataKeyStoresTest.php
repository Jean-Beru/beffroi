<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\PersonalData;

use Beffroi\Bundle\Doctrine\PersonalData\TenantDataKeyStores;
use Beffroi\Bundle\Doctrine\PersonalData\TenantScopedDataKeyStore;
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
use Symfony\Component\KeyManagement\Command\RewrapDataKeysCommand;
use Symfony\Component\KeyManagement\DataKeyHandle;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;
use Symfony\Component\KeyManagement\Exception\RuntimeException;
use Symfony\Component\KeyManagement\Test\InMemoryKms;
use Symfony\Component\KeyManagement\Test\SwitchableKms;

/**
 * The secrets the stores of the tenants bind a row with (`StoredDataKey::bindingFor()`): the first one binds
 * a new row and every one is accepted when a row is read, which is what lets a deployment rotate the secret
 * without losing what it sealed, a rewrap binding each row again under the first. And what a KMS that does
 * not answer is when a data key is asked for: an outage.
 */
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

    /**
     * A row whose secret the deployment no longer lists opens nothing: whoever wrote the table could have
     * wrapped its key themselves, and only a listed secret tells them apart.
     */
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

    /**
     * Every listed secret is accepted when a row is read, so a secret written second still opens the rows it
     * bound while it was the first.
     */
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

    /**
     * A rewrap towards the client that already wraps the keys binds each row again under the first secret,
     * after which the retired one is no longer needed: the rotation the configuration describes.
     */
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

    /**
     * Decision 0018 (issue #877): a KMS that does not answer when a data key is opened or minted is an outage,
     * the KmsUnavailableException a request is answered 503 for and served past once the KMS is back, and not
     * the failure of the component, which no listener tells from an error of the server. What the KMS said is
     * kept behind it.
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
     * The stores of the tenants under these secrets, built afresh so that nothing a previous one opened is
     * held: what a row is read with is the table and the secrets, as in a process that just started.
     *
     * @param non-empty-list<string> $secrets
     */
    private function stores(array $secrets): TenantDataKeyStores
    {
        return new TenantDataKeyStores($this->connection, $this->clients, 'op', self::MASTER_KEY, $secrets, TenantDataKeyStores::TABLE);
    }
}
