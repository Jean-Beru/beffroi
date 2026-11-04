<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Port\AtomicWritesInterface;
use Closure;

final class WritesAsTheyCome implements AtomicWritesInterface
{
    public private(set) int $units = 0;

    public private(set) bool $open = false;

    public function atomically(Closure $writes): mixed
    {
        ++$this->units;
        $this->open = true;
        try {
            return $writes();
        } finally {
            $this->open = false;
        }
    }
}
