<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Client;

use DateTimeImmutable;
use function hash;
use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Port\ClientJwksCacheInterface;
use function is_array;
use function is_int;
use Psr\Cache\CacheItemPoolInterface;
use Throwable;

/**
 * The keys read back from a "jwks_uri", kept in a pool of the application so that the workers of a
 * deployment share one read. What is written is the set and the moment it was read, as plain values and
 * not as objects: a pool outlives a deployment, and what comes back from it is read again as strictly as
 * what comes back from the party itself.
 *
 * The class is wired once per pool, the keys of the clients and the keys of the issuers a tenant trusts
 * living in one each: what tells them apart is the pool and not the key, as it is for the assertions of
 * each.
 */
final readonly class ClientJwksCache implements ClientJwksCacheInterface
{
    public function __construct(
        private CacheItemPoolInterface $cache,
        private int $lifetime,
    ) {
    }

    public function read(ClientUri $jwksUri): ?CachedClientJwks
    {
        $item = $this->cache->getItem(self::key($jwksUri));
        if (! $item->isHit()) {
            return null;
        }
        $kept = $item->get();
        if (! is_array($kept) || ! is_array($kept['keys'] ?? null) || ! is_int($kept['fetched_at'] ?? null)) {
            return null;
        }
        try {
            $keys = ClientJwks::fromDocument([
                'keys' => $kept['keys'],
            ]);
        } catch (Throwable) {
            return null;
        }

        return new CachedClientJwks($keys, new DateTimeImmutable('@' . $kept['fetched_at']));
    }

    public function write(ClientUri $jwksUri, CachedClientJwks $keys): void
    {
        $item = $this->cache->getItem(self::key($jwksUri));
        $item->set([
            'keys' => $keys->keys->keys,
            'fetched_at' => $keys->fetchedAt->getTimestamp(),
        ]);
        $item->expiresAfter($this->lifetime);
        $this->cache->save($item);
    }

    /**
     * By the URL the set was read from, hashed because a pool key takes no arbitrary character
     * (PSR-6 §Definitions).
     */
    private static function key(ClientUri $jwksUri): string
    {
        return 'beffroi.published_keys.' . hash('xxh128', $jwksUri->value);
    }
}
