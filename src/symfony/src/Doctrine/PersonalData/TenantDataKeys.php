<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\PersonalData;

use DateTimeImmutable;
use function array_keys;
use function count;
use Heidi\Core\Domain\Tenant\Tenant;
use function ksort;
use Symfony\Component\KeyManagement\RewrappableDataKeyStoreInterface;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV7;

/**
 * What a tenant holds in the data key store, read and nothing else (decision 0018): the scopes, the keys
 * of each, and for every key the instant it was minted, the master key that wraps it and the client that
 * can open it. A command that reads is not the command that writes.
 *
 * The instant comes out of the reference and not out of a column: the store draws a UUIDv7, which is why
 * its table carries no timestamp and why the newest key of a scope is the greatest reference. That also
 * makes the order of this listing the order the keys were minted in.
 */
final readonly class TenantDataKeys
{
    public function __construct(
        private RewrappableDataKeyStoreInterface $store,
    ) {
    }

    /**
     * The scopes of a tenant, each with its keys oldest first, the last of them being the one a write
     * uses. A tenant that has sealed nothing has none, which is not an error: a key is minted at the
     * first write of its family.
     *
     * @return array<string, list<StoredDataKeyDescription>> by scope, in alphabetical order
     */
    public function of(Tenant $tenant): array
    {
        $scopes = [];
        foreach ($this->store->all() as $stored) {
            if (TenantScopedEncrypter::slugOf($stored->scope) !== $tenant->slug) {
                continue;
            }
            $scopes[$stored->scope][] = new StoredDataKeyDescription(
                $stored->reference,
                self::mintedAt($stored->reference),
                $stored->wrapped->keyId,
                $stored->client,
            );
        }
        ksort($scopes);

        return $scopes;
    }

    /**
     * How many keys the tenant holds, all scopes together: what a destruction says it erased, and what a
     * rewrap says it moved.
     */
    public function countOf(Tenant $tenant): int
    {
        $total = 0;
        foreach ($this->of($tenant) as $keys) {
            $total += count($keys);
        }

        return $total;
    }

    /**
     * @return list<string> the scopes of the tenant, in alphabetical order
     */
    public function scopesOf(Tenant $tenant): array
    {
        return array_keys($this->of($tenant));
    }

    /**
     * The instant the store drew the reference, read back from the UUIDv7 it is.
     */
    private static function mintedAt(string $reference): ?DateTimeImmutable
    {
        if (! Uuid::isValid($reference, Uuid::FORMAT_BINARY)) {
            return null;
        }
        $uuid = Uuid::fromBinary($reference);

        // Only a UUIDv7 carries the instant it was drawn. A reference of another shape is a row something
        // else wrote, and this says it does not know rather than deriving an instant from nothing.
        return $uuid instanceof UuidV7 ? $uuid->getDateTime() : null;
    }
}
