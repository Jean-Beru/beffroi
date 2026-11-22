<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Message\SyncMessage;

final readonly class WriteBeforeAnswering implements SyncMessage
{
    public function __construct(
        public string $what,
    ) {
    }
}
