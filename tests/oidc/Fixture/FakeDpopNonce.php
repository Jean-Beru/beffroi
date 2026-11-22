<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use DateTimeImmutable;
use Beffroi\Oidc\Exception\UseDpopNonceException;
use Beffroi\Oidc\Port\DpopNonceInterface;

/**
 * RFC 9449 §8
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

        throw new UseDpopNonceException(
            $this->nonce,
            $nonce === null
                ? 'This provider asks a DPoP proof to carry a nonce it issued (RFC 9449 section 8).'
                : 'The DPoP proof carries a nonce this provider no longer accepts (RFC 9449 section 8).',
        );
    }
}
