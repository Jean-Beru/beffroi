<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AmbientTenantInterface;
use function is_resource;
use function is_string;
use Psr\Container\ContainerInterface;
use SensitiveParameter;
use function sprintf;
use function stream_get_contents;
use Symfony\Component\KeyManagement\BlindIndex;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;
use Symfony\Component\KeyManagement\DataKeyStoreInterface;
use Throwable;

/**
 * The blind index of a column for one tenant, over the index key of that tenant (decisions 0011 and 0018).
 *
 * The key is a row of the data key store in a scope of its own, on a store whose maximum age is null: the
 * age past which a key is retired is a setting of a store and not of a scope, and an index key must never
 * be retired nor rotated, every tag already written having been derived under it. Keeping it in the store
 * rather than beside `kms_key_id` on the tenant is what makes `key-management:rewrap-data-keys` carry it
 * along when a deployment changes master key or backend, which is the fourth success criterion of the
 * spike, with no second command to forget.
 *
 * **The row is read here rather than asked of the store.** `BlindIndex` takes a wrapped key and unwraps it
 * itself, and no method of the store hands a wrapped key back: `current()` returns a handle, having
 * unwrapped it already, so going through it would open one key twice where decision 0018 counts one
 * opening per data key and per thread. The store is only asked when the row is missing, which happens once
 * in the life of a tenant and which mints rather than opens. That a store cannot hand back the wrapped key
 * of a scope is the third thing this spike asks of the bridges, and it is written in decision 0018 rather
 * than worked around quietly.
 *
 * **The key of a scope is its first row and not its newest**, which is the one place this reads the table
 * differently from the store. A second row in an index scope is a rotation nothing asked for, and reading
 * it would leave every tag already written unreachable; reading the first keeps them.
 *
 * One index per tenant and per projection, built at its first use and held for as long as this object,
 * which is as long as the process: nothing here carries `kernel.reset`, for the reason decision 0018 gives
 * the stores.
 */
final class TenantBlindIndexes
{
    /**
     * @var array<string, array<string, BlindIndex>> by the slug of the tenant, then by the property the
     *                                               tag is written to
     */
    private array $indexes = [];

    /**
     * @param ContainerInterface $clients the KMS clients of the deployment, by the name the configuration
     *                                    gives them, so that a row is unwrapped by whoever wrapped it
     * @param DataKeyStoreInterface $store the store of the index scopes, the one whose keys never retire
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly ContainerInterface $clients,
        private readonly DataKeyStoreInterface $store,
        private readonly AmbientTenantInterface $tenants,
        private readonly string $table,
    ) {
    }

    /**
     * @throws RuntimeException when no tenant is ambient
     */
    public function of(BlindIndexedColumn $column): BlindIndex
    {
        $slug = $this->slug($column);

        return $this->indexes[$slug][$column->tag] ??= $this->build($slug, $column);
    }

    private function build(string $slug, BlindIndexedColumn $column): BlindIndex
    {
        $scope = TenantScopedEncrypter::scope($slug, BlindIndexedColumns::SCOPE);
        $row = $this->row($scope);

        if ($row === null) {
            // The scope has no key yet. Asking the store for its current one mints it, which costs the KMS
            // a generation and not an opening, and the row is then there to be read.
            $this->store->current($scope);
            $row = $this->row($scope) ?? throw new RuntimeException(sprintf(
                'The data key store minted no row for the index scope "%s", so no blind index can be derived for that tenant.',
                $scope,
            ));
        }

        [$wrapped, $client] = $row;

        return $column->index($this->generator($client), $wrapped);
    }

    /**
     * The wrapped index key of a scope and the client that can open it, or null when the scope has none.
     *
     * @return array{Ciphertext, string}|null
     *
     * @throws RuntimeException if the row says nothing of what wrapped it
     */
    private function row(string $scope): ?array
    {
        $row = $this->connection
            ->createQueryBuilder()
            ->select('key_material', 'master_key_id', 'client')
            ->from($this->table)
            ->where('scope = :scope')
            ->setParameter('scope', $scope)
            ->orderBy('id', 'ASC')
            ->setMaxResults(1)
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        $masterKeyId = $row['master_key_id'];
        $client = $row['client'];

        if (! is_string($masterKeyId) || ! is_string($client)) {
            throw new RuntimeException(sprintf(
                'The row of the index scope "%s" names no master key or no KMS client, so nothing can open it: a data key is unwrapped by whoever wrapped it.',
                $scope,
            ));
        }

        return [new Ciphertext(self::bytes($row['key_material']), $masterKeyId), $client];
    }

    /**
     * @throws RuntimeException when the row names a client this deployment does not have
     */
    private function generator(string $client): DataKeyGeneratorInterface
    {
        $kms = $this->clients->has($client) ? $this->clients->get($client) : null;

        if (! $kms instanceof DataKeyGeneratorInterface) {
            throw new RuntimeException(sprintf(
                'The index key of this tenant was wrapped by the KMS client "%s", which this deployment does not have, so no blind index can be derived: configure that client, or rewrap the row with "key-management:rewrap-data-keys".',
                $client,
            ));
        }

        return $kms;
    }

    /**
     * A tag is derived for the tenant that is ambient, the same one the value beside it is sealed for: a
     * row sealed for one tenant and indexed for another would be a row its own tenant cannot find and
     * another tenant can (decision 0018).
     *
     * @throws RuntimeException when no tenant is ambient
     */
    private function slug(BlindIndexedColumn $column): string
    {
        try {
            return $this->tenants->provide()->slug;
        } catch (Throwable $exception) {
            throw new RuntimeException(
                sprintf(
                    'No tenant is ambient, so the blind index of "%s" cannot be derived: a tag derived under the index key of another tenant is a tag no search of either tenant matches.',
                    $column->tag,
                ),
                0,
                $exception,
            );
        }
    }

    /**
     * A binary column comes back as a string on some platforms and as a stream on others, which anything
     * reading this table has to settle before it can parse it; DBAL's own binary type does the same.
     */
    private static function bytes(#[SensitiveParameter] mixed $value): string
    {
        if (is_resource($value)) {
            return (string) stream_get_contents($value);
        }

        return is_string($value) ? $value : '';
    }
}
