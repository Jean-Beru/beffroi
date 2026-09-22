<?php

declare(strict_types=1);

namespace Heidi\Bundle\Dpop;

use DateTimeImmutable;
use function hash;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Port\DpopProofReplayGuardInterface;
use Psr\Cache\CacheItemPoolInterface;
use function sprintf;

/**
 * The "jti" of the proofs already seen, kept in a pool of the application until the proof they belong to
 * stops being accepted (RFC 9449 §11.1), so that a proof taken off the wire cannot be sent again, on
 * this worker or on another. A pool tells a hit from a miss and not an insertion from a replacement:
 * two identical proofs racing on the same millisecond could both be taken, which is a narrower window
 * than the one a replay needs and is what a shared pool gives; a store that can add atomically would
 * close it.
 */
final readonly class CachedDpopProofReplayGuard implements DpopProofReplayGuardInterface
{
    public function __construct(
        private CacheItemPoolInterface $cache,
    ) {
    }

    public function remember(KeyConfirmation $key, string $jti, DateTimeImmutable $expiresAt): bool
    {
        $item = $this->cache->getItem(self::key($key, $jti));
        if ($item->isHit()) {
            return false;
        }
        $item->set($expiresAt->getTimestamp());
        $item->expiresAt($expiresAt);
        $this->cache->save($item);

        return true;
    }

    /**
     * Per key: it is the holder of a key that chooses the "jti" of its proofs, and two clients may
     * choose the same one.
     */
    private static function key(KeyConfirmation $key, string $jti): string
    {
        return 'heidi.dpop_proofs.' . hash('xxh128', sprintf('%s|%s', $key->thumbprint, $jti));
    }
}
