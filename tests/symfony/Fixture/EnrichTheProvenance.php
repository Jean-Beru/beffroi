<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Message\Command;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0018
 */
final readonly class EnrichTheProvenance implements Command
{
    public function __construct(
        public Uuid $sessionId,
    ) {
    }
}
