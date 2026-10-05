<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AmbientTenantInterface;
use function is_resource;
use function is_string;
use SensitiveParameter;
use function sprintf;
use function stream_get_contents;
use Symfony\Component\KeyManagement\BlindIndexInterface;
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
 * **The key is opened by the store, once for every index over it.** `StoredKeyBlindIndex` derives its tags
 * under a data key the store holds and names it by reference, so the four columns of a tenant share the one
 * opening that store did, which is what decision 0018 counts: one opening per data key and per thread. The
 * store is asked for the row only when there is none, which happens once in the life of a tenant and which
 * mints rather than opens.
 *
 * **By reference and not by scope**, which is also what the component asks of a caller: `current()` is free
 * to retire a key and mint another, and for an index that would leave every tag already written unreachable.
 * The reference is read from the table, and it is that of the **first** row of the scope and not of its
 * newest, which is the one place this reads the table differently from the store: a second row in an index
 * scope is a rotation nothing asked for, and the first is the one every tag was derived under.
 *
 * One index per tenant and per column, built at its first use and held for as long as this object,
 * which is as long as the process: nothing here carries `kernel.reset`, for the reason decision 0018 gives
 * the stores.
 */
final class TenantBlindIndexes
{
    /**
     * @var array<string, array<string, BlindIndexInterface>> by the slug of the tenant, then by the property the
     *                                               tag is written to
     */
    private array $indexes = [];

    /**
     * @param DataKeyStoreInterface $store the store of the index scopes, the one whose keys never retire,
     *                                     and the one that opens a row for every index over it
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly DataKeyStoreInterface $store,
        private readonly AmbientTenantInterface $tenants,
        private readonly string $table,
    ) {
    }

    /**
     * @throws RuntimeException when no tenant is ambient
     */
    public function of(BlindIndexedColumn $column): BlindIndexInterface
    {
        $slug = $this->slug($column);

        return $this->indexes[$slug][$column->tag] ??= $this->build($slug, $column);
    }

    private function build(string $slug, BlindIndexedColumn $column): BlindIndexInterface
    {
        $scope = TenantScopedEncrypter::scope($slug, BlindIndexedColumns::SCOPE);
        $reference = $this->reference($scope);

        if ($reference === null) {
            // The scope has no key yet. Asking the store for its current one mints it, which costs the KMS
            // a generation and not an opening, and the row is then there to be read.
            $this->store->current($scope);
            $reference = $this->reference($scope) ?? throw new RuntimeException(sprintf(
                'The data key store minted no row for the index scope "%s", so no blind index can be derived for that tenant.',
                $scope,
            ));
        }

        return $column->index($this->store, $reference);
    }

    /**
     * The reference of the index key of a scope, which is that of its first row, or null when the scope has
     * no row at all.
     */
    private function reference(string $scope): ?string
    {
        $reference = $this->connection
            ->createQueryBuilder()
            ->select('id')
            ->from($this->table)
            ->where('scope = :scope')
            ->setParameter('scope', $scope)
            ->orderBy('id', 'ASC')
            ->setMaxResults(1)
            ->fetchOne();

        return $reference === false ? null : self::bytes($reference);
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
