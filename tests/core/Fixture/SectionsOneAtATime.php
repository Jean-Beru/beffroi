<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Port\ExclusiveSectionsInterface;
use Closure;

/**
 * One process: a section runs as it comes, and the names of those entered are kept.
 */
final class SectionsOneAtATime implements ExclusiveSectionsInterface
{
    /**
     * @var list<string>
     */
    public private(set) array $entered = [];

    public private(set) ?string $open = null;

    public function exclusively(string $name, Closure $section): mixed
    {
        $this->entered[] = $name;
        $this->open = $name;
        try {
            return $section();
        } finally {
            $this->open = null;
        }
    }
}
