<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateTimeImmutable;
use Heidi\Oidc\Exception\UseDpopNonceException;
use Heidi\Oidc\Port\DpopNonceInterface;

/**
 * A provider that asks for one nonce and always the same one, so that a test can say what it hands back
 * and what it takes (RFC 9449 §8).
 */
final readonly class FakeDpopNonce implements DpopNonceInterface
{
    public function __construct(
        private string $nonce,
    ) {
    }

    public function verify(?string $nonce, DateTimeImmutable $now): void
    {
        if ($nonce === $this->nonce) {
            return;
        }

        throw new UseDpopNonceException($this->nonce, $nonce === null
            ? 'This provider asks a DPoP proof to carry a nonce it issued (RFC 9449 section 8).'
            : 'The DPoP proof carries a nonce this provider no longer accepts (RFC 9449 section 8).');
    }
}
