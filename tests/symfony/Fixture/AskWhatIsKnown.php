<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Message\Query;

/**
 * Decision 0020
 */
final readonly class AskWhatIsKnown implements Query
{
    public function __construct(
        public string $about,
    ) {
    }
}
