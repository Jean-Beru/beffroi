<?php

declare(strict_types=1);

namespace Heidi\Bundle\Client;

use DateTimeImmutable;
use function hash;
use Heidi\Oidc\Domain\Client\CachedClientJwks;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Port\ClientJwksCacheInterface;
use function is_array;
use function is_int;
use Psr\Cache\CacheItemPoolInterface;
use function sprintf;
use Throwable;

/**
 * The keys read back from a client's "jwks_uri", kept in a pool of the application so that the workers
 * of a deployment share one fetch. What is written is the set and the moment it was read, as plain
 * values and not as objects: a pool outlives a deployment, and what comes back from it is read again as
 * strictly as what comes back from the client itself.
 */
final readonly class ClientJwksCache implements ClientJwksCacheInterface
{
    public function __construct(
        private CacheItemPoolInterface $cache,
        private int $lifetime,
    ) {
    }

    public function read(Client $client): ?CachedClientJwks
    {
        $item = $this->cache->getItem(self::key($client));
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

    public function write(Client $client, CachedClientJwks $keys): void
    {
        $item = $this->cache->getItem(self::key($client));
        $item->set([
            'keys' => $keys->keys->keys,
            'fetched_at' => $keys->fetchedAt->getTimestamp(),
        ]);
        $item->expiresAfter($this->lifetime);
        $this->cache->save($item);
    }

    /**
     * Per tenant and per client; the identifiers are hashed because a pool key takes no arbitrary
     * character (PSR-6 §Definitions).
     */
    private static function key(Client $client): string
    {
        return 'heidi.client_keys.' . hash('xxh128', sprintf('%s|%s', $client->tenant->id->toRfc4122(), $client->registration->clientId));
    }
}
