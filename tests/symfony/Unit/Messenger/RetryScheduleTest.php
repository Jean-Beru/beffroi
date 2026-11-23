<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use App\Messenger\RetrySchedule;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

final class RetryScheduleTest extends TestCase
{
    #[Test]
    public function aNumberBelowItsFloorIsRefusedUnderTheNodeItIsReadFrom(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "notices.retries" is a number of retries of at least 0, -1 given.');

        // When
        new RetrySchedule(-1, 60, 2, 3600, 'notices');
    }
}
