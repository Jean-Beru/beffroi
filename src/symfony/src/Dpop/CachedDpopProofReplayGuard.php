<?php

declare(strict_types=1);

namespace Heidi\Bundle\Dpop;

use DateTimeImmutable;
use function hash;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Port\DpopProofReplayGuardInterface;
use Heidi\Bundle\Cache\SeenOnce;
use function sprintf;

/**
 * The "jti" of the proofs already seen (RFC 9449 §11.1), so that a proof taken off the wire cannot be
 * sent again. What makes a "jti" unique is all this says; remembering it once is SeenOnce's, with the
 * caveat that goes with a pool.
 */
final readonly class CachedDpopProofReplayGuard implements DpopProofReplayGuardInterface
{
    public function __construct(
        private SeenOnce $seen,
    ) {
    }

    public function remember(KeyConfirmation $key, string $jti, DateTimeImmutable $expiresAt): bool
    {
        return $this->seen->remember(self::key($key, $jti), $expiresAt);
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
