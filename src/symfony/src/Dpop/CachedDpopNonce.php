<?php

declare(strict_types=1);

namespace Heidi\Bundle\Dpop;

use DateInterval;
use DateTimeImmutable;
use function hash;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\UseDpopNonceException;
use Heidi\Oidc\Port\DpopNonceInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * A provider that asks a proof to carry a nonce of its own (RFC 9449 §8): a value drawn the way this
 * provider draws every value it hands out and recognises later, kept in a pool the workers share until
 * it expires. A proof carrying one was
 * made after the provider issued it, which is what a nonce is for: the "iat" of a proof is what its
 * client says, the nonce is what the provider knows.
 *
 * A nonce stands for its whole lifetime and is not spent by the first proof that carries it: what makes
 * one proof of it is its "jti", which is remembered on its own. The client keeps nothing but the last
 * nonce it was handed, until its next request.
 */
final readonly class CachedDpopNonce implements DpopNonceInterface
{
    public function __construct(
        private CacheItemPoolInterface $cache,
        private DateInterval $lifetime,
    ) {
    }

    public function verify(?string $nonce, DateTimeImmutable $now): void
    {
        if ($nonce !== null && $this->cache->getItem(self::key($nonce))->isHit()) {
            return;
        }

        throw new UseDpopNonceException(
            $this->issue($now),
            $nonce === null
                ? 'This provider asks a DPoP proof to carry a nonce it issued (RFC 9449 section 8).'
                : 'The DPoP proof carries a nonce this provider no longer accepts (RFC 9449 section 8).',
        );
    }

    private function issue(DateTimeImmutable $now): string
    {
        $nonce = DrawnSecret::draw();
        $item = $this->cache->getItem(self::key($nonce));
        $item->set($now->getTimestamp());
        $item->expiresAt($now->add($this->lifetime));
        $this->cache->save($item);

        return $nonce;
    }

    private static function key(string $nonce): string
    {
        return 'heidi.dpop_nonces.' . hash('xxh128', $nonce);
    }
}
