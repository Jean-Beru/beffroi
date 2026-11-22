<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Symfony\Contracts\Service\ResetInterface;

final class CountedResets implements ResetInterface
{
    public private(set) int $resets = 0;

    public function reset(): void
    {
        ++$this->resets;
    }
}
