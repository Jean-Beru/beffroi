<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_key_last;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SignedCheckpointsInterface;

final class KeptCheckpoints implements SignedCheckpointsInterface
{
    /**
     * @var list<non-empty-string> every one kept, the last one last
     */
    public private(set) array $kept = [];

    public function last(Tenant $tenant): ?string
    {
        $last = array_key_last($this->kept);

        return $last === null ? null : $this->kept[$last];
    }

    public function keep(Tenant $tenant, string $compactJws): void
    {
        if ($compactJws !== '') {
            $this->kept[] = $compactJws;
        }
    }

    /**
     * @param non-empty-string $compactJws
     */
    public function putBack(string $compactJws): void
    {
        $this->kept[] = $compactJws;
    }

    public function removeAll(): void
    {
        $this->kept = [];
    }
}
