<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\Timeout;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
