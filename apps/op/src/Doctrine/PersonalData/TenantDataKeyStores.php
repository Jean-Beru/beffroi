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
 * One data key store per tenant, behind one reader (decision 0018).
 *
 * `DataKeyStore` takes one client and one master key for the whole store, and `current()` and `rotate()`
 * wrap with them, so a master key per tenant is a store per tenant. `get()` does not: it reads the client
 * and the master key back from the row, so **a read resolves whatever wrote it** and needs no routing at
 * all, which is what keeps this small. Walking the rows and rewrapping them are reads of the same kind, so
 * they go to the same one reader; only what wraps is routed.
 *
 * The store of a tenant is built at its first use and held, keyed by slug, each one with the master key
 * `KmsKeyId` resolves for that slug, the one its signing keys are already sealed under.
 *
 * **A KMS that does not answer is an outage here as for every key of the provider** (`KeyManagementFailure`):
 * what opens or mints a data key fails with `KmsUnavailableException`, whatever asked for it, a sealed column or
 * a blind index, and a request is answered with the 503 it is served past once the KMS is back
 * (`KmsUnavailableListener`). What the component refuses, a row it cannot find or whose binding does not hold,
 * is thrown as the component threw it, which is what the contract of a store names.
 *
 * **Every store is given the same secrets.** A row is bound to its reference and its scope by an HMAC keyed
 * by its data key and by a secret of the store (`StoredDataKey::bindingFor()`), so a key that whoever
 * writes the table wrapped themselves opens nothing: the first secret writes the binding of a new row and
 * every one reads it back. A row is read by the one reader whatever tenant it belongs to, so the secrets of
 * a deployment are one list and not one per tenant, and a rewrap is what moves a row to the first of them.
 *
 * **Nothing here carries `kernel.reset`.** The component tags its own store with it, and `forget()`
 * releases every retained plaintext between two units of work; under FrankenPHP in worker mode that puts
 * the KMS back on the path of every request that touches a column, which the third success criterion of
 * the spike forbids. A thread keeps open what it has opened, as it already keeps an open signing key
 * (`SealedKeyProvider`), and what that costs is written in decision 0018 rather than discovered later.
 */
final class TenantDataKeyStores implements RewrappableDataKeyStoreInterface
{
    /**
     * The table the wrapped data keys of every tenant live in, owned by this provider and created by one of
     * its migrations: the bridge is clear that a table carrying anything its store does not know about is
     * a table the application declares itself, and this one carries exactly the six columns it names.
     */
    public const string TABLE = 'beffroi_data_key';

    /**
     * How many bytes a data key holds, which is what AES-256-GCM takes.
     */
    private const int KEY_BYTES = 32;

    /**
     * @var array<string, DataKeyStore> by the slug of the tenant whose master key wraps what it writes
     */
    private array $stores = [];

    /**
     * The one store every read goes to, built at its first use.
     */
    private ?DataKeyStore $reader = null;

    /**
     * @param ContainerInterface $clients the KMS clients of the deployment, by the name the configuration
     *                                    gives them
     * @param string $client the name of the one this deployment seals with
     * @param string $masterKeyId the pattern of the master key of a tenant, "{tenant}" standing for its
     *                            slug, the same pattern the signing keys are sealed under
     * @param non-empty-list<string> $secrets what binds a row to its reference and its scope, the first one
     *                                        writing and every one reading
     * @param int<0, max>|null $maxAgeSeconds the age past which a scope is given a new key, null never
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
     * @throws KmsUnavailableException when the KMS does not answer to open or mint the key
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
     * The key of a scope retired and a new one minted, whatever the age of the one that was current: what
     * the console asks for when a tenant has a reason not to wait for the age of its keys.
     *
     * @throws KmsUnavailableException when the KMS does not answer to mint the key
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
     * @throws KmsUnavailableException when the KMS does not answer to open the key
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

    /**
     * A read of the row like the two above, so the reader answers: every store of this router binds the
     * same context, the default of the bridge, whatever the tenant whose master key wraps the row.
     */
    public function wrappingContextOf(StoredDataKey $row): string
    {
        return $this->reader()->wrappingContextOf($row);
    }

    /**
     * The store that wraps for the tenant a scope names, built once and held.
     */
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
     * The one store every read goes to. Its master key is the pattern unresolved, which nothing on this
     * path uses: `get()`, `all()` and `rewrap()` take the client and the master key of the row they read,
     * and a reference belongs to no tenant until the row says so.
     *
     * It is public because it is also what declares the table in the schema the ORM assembles: the
     * listener of the ORM bridge asks a `DataKeyStore` and not this router, and the table of a read is the
     * table of every write.
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
