<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\IssuedJwsKindInterface;

/**
 * A kind of JWS with the lifetime given, or one the tenant does not issue (null).
 */
final readonly class FixedLifetimeJwsKind implements IssuedJwsKindInterface
{
    public function __construct(
        private ?DateInterval $lifetime,
    ) {
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->lifetime;
    }
}
