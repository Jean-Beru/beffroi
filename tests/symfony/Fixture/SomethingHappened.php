<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Message\Event;

/**
 * Decision 0020
 */
final readonly class SomethingHappened implements Event
{
    public function __construct(
        public string $what,
    ) {
    }
}
