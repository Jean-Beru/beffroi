<?php

declare(strict_types=1);

namespace Heidi\Bundle\Client;

use DateTimeImmutable;
use function hash;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Psr\Cache\CacheItemPoolInterface;
use function sprintf;

/**
 * The "jti" of the client assertions already seen, kept in a pool of the application until the assertion
 * they belong to expires (RFC 7523 §3, §4), so that an assertion authenticates once and does so across
 * the workers of a deployment. A pool tells a hit from a miss and not an insertion from a replacement:
 * two identical assertions racing on the same millisecond could both be taken, which is a narrower
 * window than the one a replay needs and is what a shared pool gives; a store that can add atomically
 * would close it.
 */
final readonly class ClientAssertionReplayGuard implements ClientAssertionReplayGuardInterface
{
    public function __construct(
        private CacheItemPoolInterface $cache,
    ) {
    }

    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool
    {
        $item = $this->cache->getItem(self::key($client, $jti));
        if ($item->isHit()) {
            return false;
        }
        $item->set($expiresAt->getTimestamp());
        $item->expiresAt($expiresAt);
        $this->cache->save($item);

        return true;
    }

    /**
     * Per tenant and per client: RFC 7523 §3 makes a "jti" unique to the issuer of the assertion, and
     * two clients may use the same one.
     */
    private static function key(Client $client, string $jti): string
    {
        return 'heidi.client_assertions.' . hash('xxh128', sprintf('%s|%s|%s', $client->tenant->id->toRfc4122(), $client->registration->clientId, $jti));
    }
}
