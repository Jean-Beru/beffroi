<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;

/**
 * A kind of artifact bound to a key of the use given, with the lifetime given, or one the tenant does not
 * issue (null).
 */
final readonly class FixedLifetimeArtifact implements KeyBoundArtifactInterface
{
    public function __construct(
        private ?DateInterval $lifetime,
        private KeyUse $keyUse = KeyUse::Signature,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return $this->keyUse;
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->lifetime;
    }
}
