<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

/**
 * One call the demonstration makes to this provider to take a hop (issue #462): where, how, with which
 * fields, and with which access token when the hop is one a token is presented at.
 */
final readonly class DrivenCall
{
    /**
     * @param array<string, string> $fields
     */
    public function __construct(
        public string $method,
        public string $url,
        public array $fields = [],
        public ?string $bearer = null,
    ) {
    }
}
