<?php

declare(strict_types=1);

namespace App\Http;

/**
 * Seconds one call to a third party is given, connection included, which HttpClient reads twice: as the longest it
 * waits for a byte, "timeout", and as the longest the whole exchange takes, "max_duration". A third party that hangs
 * then holds neither a worker nor a person waiting on it; how many times the call is made again is the caller's.
 */
final readonly class Timeout
{
    /**
     * The shortest a configuration gives a call, a written number and one of the environment alike (BoundedNumber).
     */
    public const float MINIMUM = 0.1;

    public function __construct(
        public float $seconds,
    ) {
    }

    /**
     * @return array{timeout: float, max_duration: float}
     */
    public function options(): array
    {
        return [
            'timeout' => $this->seconds,
            'max_duration' => $this->seconds,
        ];
    }
}
