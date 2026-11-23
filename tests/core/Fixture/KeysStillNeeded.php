<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\RetirementHoldInterface;
use function in_array;

final readonly class KeysStillNeeded implements RetirementHoldInterface
{
    public const string NAME = 'a body a test keeps';

    /**
     * @param list<string> $kids
     */
    public function __construct(
        private array $kids,
    ) {
    }

    public function holds(TenantKey $key): bool
    {
        return in_array($key->kid, $this->kids, true);
    }

    public function name(): string
    {
        return self::NAME;
    }
}
