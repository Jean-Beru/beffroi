<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\OutboundSection;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Decision 0006
 */
final class OutboundSectionTest extends TestCase
{
    #[Test]
    public function theGuardReachesTheNetworksTheEnvironmentNames(): void
    {
        // When
        $guard = OutboundSection::guard(['10.20.0.0/16', 'fd00:20::/32']);

        // Then
        static::assertSame(['10.20.0.0/16', 'fd00:20::/32'], $guard->reachable);
    }

    #[Test]
    public function theGuardReachesNoNetworkByDefault(): void
    {
        // When / Then
        static::assertSame([], OutboundSection::guard([])->reachable);
    }

    #[Test]
    public function aListHoldingSomethingOtherThanTextIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "outbound.reachable_private_networks" must be a list of strings.');

        // When
        OutboundSection::guard([10]);
    }
}
