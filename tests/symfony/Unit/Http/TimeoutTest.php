<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\Timeout;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A call to a third party is given its timeout twice by HttpClient, for a byte and for the whole exchange, so that a
 * party that answers one byte a second holds nobody longer than one that answers none.
 */
final class TimeoutTest extends TestCase
{
    #[Test]
    public function theTimeoutBoundsTheWaitForAByteAndTheWholeExchange(): void
    {
        // When / Then
        static::assertSame(
            [
                'timeout' => 2.5,
                'max_duration' => 2.5,
            ],
            new Timeout(2.5)->options(),
        );
    }
}
