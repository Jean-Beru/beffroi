<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use Beffroi\Core\Bridge\KeyManagement\KmsKeyId;
use Psr\Container\ContainerInterface;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\DataKeyStore;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKeyHandle;
use Symfony\Component\KeyManagement\RewrappableDataKeyStoreInterface;

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
 * **Nothing here carries `kernel.reset`.** The component tags its own store with it, and `forget()`
 * releases every retained plaintext between two units of work; under FrankenPHP in worker mode that puts
 * the KMS back on the path of every request that touches a column, which the third success criterion of
 * the spike forbids. A thread keeps open what it has opened, as it already keeps an open signing key
 * (`SealedKeyProvider`), and what that costs is written in decision 0018 rather than discovered later.
 */
final class TenantDataKeyStores implements RewrappableDataKeyStoreInterface
{
    /**
     * The table the wrapped data keys of every tenant live in, owned by this bundle and created by one of
     * its migrations: the bridge is clear that a table carrying anything its store does not know about is
     * a table the application declares itself, and this one carries exactly the five columns it names.
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
     * @param int<0, max>|null $maxAgeSeconds the age past which a scope is given a new key, null never
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly ContainerInterface $clients,
        private readonly string $client,
        private readonly string $masterKeyId,
        private readonly string $table,
        private readonly ?int $maxAgeSeconds = DataKeyStore::DEFAULT_MAX_AGE_SECONDS,
    ) {
    }

    public function current(string $scope): DataKeyHandle
    {
        return $this->of($scope)->current($scope);
    }

    /**
     * The key of a scope retired and a new one minted, whatever the age of the one that was current: what
     * the console asks for when a tenant has a reason not to wait for the age of its keys.
     */
    public function rotate(string $scope): DataKeyHandle
    {
        return $this->of($scope)->rotate($scope);
    }

    public function get(string $reference): DataKeyHandle
    {
        return $this->reader()->get($reference);
    }

    public function all(?string $client = null): iterable
    {
        return $this->reader()->all($client);
    }

    public function rewrap(string $reference, Ciphertext $wrapped, string $client): void
    {
        $this->reader()->rewrap($reference, $wrapped, $client);
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
            $this->table,
            self::KEY_BYTES,
            $this->maxAgeSeconds,
        );
    }
}
