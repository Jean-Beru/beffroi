<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Cache;

use DateTimeImmutable;
use Psr\Cache\CacheItemPoolInterface;

/**
 * An identifier taken once, in a pool the workers of a deployment share: it is remembered until what
 * carries it stops being accepted, so that what was taken off the wire cannot be sent again, on this
 * worker or on another.
 *
 * A pool tells a hit from a miss and not an insertion from a replacement: two identical identifiers
 * racing on the same millisecond could both be taken, which is a narrower window than the one a replay
 * needs and is what a shared pool gives; a store that can add atomically would close it. That is one
 * rule and one caveat, so whoever guards against a replay composes the identifier and reads it here.
 */
final readonly class SeenOnce
{
    public function __construct(
        private CacheItemPoolInterface $cache,
    ) {
    }

    /**
     * @param string $key what makes the identifier unique, as the guard composes it
     * @param DateTimeImmutable $expiresAt when what carries it stops being accepted, after which it may
     *                                     be forgotten
     *
     * @return bool true when it had not been seen and is now remembered, false when it had
     */
    public function remember(string $key, DateTimeImmutable $expiresAt): bool
    {
        $item = $this->cache->getItem($key);
        if ($item->isHit()) {
            return false;
        }
        $item->set($expiresAt->getTimestamp());
        $item->expiresAt($expiresAt);
        $this->cache->save($item);

        return true;
    }
}
