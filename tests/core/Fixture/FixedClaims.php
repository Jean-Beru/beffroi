<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Identity\Claim\ClaimInterface;
use Beffroi\Core\Port\ClaimsInterface;
use function array_find;

/**
 * The claims a person is described with in a deployment under test (issue #846): the ones a test wires, and
 * none unless it wires some.
 */
final readonly class FixedClaims implements ClaimsInterface
{
    /**
     * @param list<ClaimInterface> $claims
     */
    public function __construct(
        private array $claims = [],
    ) {
    }

    public function named(string $name): ?ClaimInterface
    {
        return array_find($this->claims, static fn (ClaimInterface $claim): bool => $claim->name() === $name);
    }
}
