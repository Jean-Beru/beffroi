<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use Beffroi\Core\Bridge\KeyManagement\KeyManagementFailure;
use Beffroi\Core\Bridge\KeyManagement\KmsKeyId;
use Beffroi\Core\Exception\KmsUnavailableException;
use Psr\Container\ContainerInterface;
use SensitiveParameter;
use function sprintf;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;
use Symfony\Component\KeyManagement\DataKey;
use Symfony\Component\KeyManagement\DataKeyHandle;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementRuntimeException;
use Symfony\Component\KeyManagement\RewrappableDataKeyStoreInterface;
use Symfony\Component\KeyManagement\StoredDataKey;

/**
 * One store per tenant for what wraps, and one reader for every read, which takes the client and the master key from
 * the row it reads.
 */
final class TenantDataKeyStores implements RewrappableDataKeyStoreInterface
{
    public const string TABLE = 'beffroi_data_key';

    private const int KEY_BYTES = 32;

    /**
     * @var array<string, DataKeyStore> by tenant slug
     */
    private array $stores = [];

    private ?DataKeyStore $reader = null;

    /**
     * @param ContainerInterface $clients the KMS clients, by configured name
     * @param string $masterKeyId a pattern, "{tenant}" standing for the slug
     * @param non-empty-list<string> $secrets the first writes, every one reads
     * @param int<0, max>|null $maxAgeSeconds null for never
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly ContainerInterface $clients,
        private readonly string $client,
        private readonly string $masterKeyId,
        #[SensitiveParameter]
        private readonly array $secrets,
        private readonly string $table,
        private readonly ?int $maxAgeSeconds = DataKeyStore::DEFAULT_MAX_AGE_SECONDS,
    ) {
    }

    /**
     * @throws KmsUnavailableException
     */
    public function current(string $scope): DataKeyHandle
    {
        try {
            return $this->of($scope)->current($scope);
        } catch (KeyManagementRuntimeException $exception) {
            throw KeyManagementFailure::outageOf($exception, sprintf('The data key of the scope "%s" could not be opened or minted.', $scope)) ?? $exception;
        }
    }

    /**
     * @throws KmsUnavailableException
     */
    public function rotate(string $scope): DataKeyHandle
    {
        try {
            return $this->of($scope)->rotate($scope);
        } catch (KeyManagementRuntimeException $exception) {
            throw KeyManagementFailure::outageOf($exception, sprintf('No new data key could be minted for the scope "%s".', $scope)) ?? $exception;
        }
    }

    /**
     * @throws KmsUnavailableException
     */
    public function get(string $reference): DataKeyHandle
    {
        try {
            return $this->reader()->get($reference);
        } catch (KeyManagementRuntimeException $exception) {
            throw KeyManagementFailure::outageOf($exception, 'The data key of a sealed value could not be opened.') ?? $exception;
        }
    }

    public function all(?string $client = null): iterable
    {
        return $this->reader()->all($client);
    }

    public function rewrap(StoredDataKey $row, DataKey $rewrapped, string $client): void
    {
        $this->reader()->rewrap($row, $rewrapped, $client);
    }

    public function wrappingContextOf(StoredDataKey $row): string
    {
        return $this->reader()->wrappingContextOf($row);
    }

    private function of(string $scope): DataKeyStore
    {
        $slug = TenantScopedEncrypter::slugOf($scope);

        return $this->stores[$slug] ??= new DataKeyStore(
            $this->connection,
            $this->clients,
            $this->client,
            new KmsKeyId($this->masterKeyId)->forSlug($slug),
            $this->secrets,
            $this->table,
            self::KEY_BYTES,
            $this->maxAgeSeconds,
        );
    }

    /**
     * Its master key is the pattern unresolved, which no read uses. Public, because the listener of the ORM bridge
     * declares the table through a DataKeyStore.
     */
    public function reader(): DataKeyStore
    {
        return $this->reader ??= new DataKeyStore(
            $this->connection,
            $this->clients,
            $this->client,
            $this->masterKeyId,
            $this->secrets,
            $this->table,
            self::KEY_BYTES,
            $this->maxAgeSeconds,
        );
    }
}
