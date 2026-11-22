<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Ciba;

use Beffroi\Oidc\Application\Ciba\DeliveryModeNames;
use Beffroi\Oidc\Application\Ciba\ServedDeliveryModes;
use Beffroi\Oidc\Domain\Ciba\PingDelivery;
use Beffroi\Oidc\Domain\Ciba\PollDelivery;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\DeliveryModes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §4
 */
final class ServedDeliveryModesTest extends TestCase
{
    #[Test]
    public function itServesWhatIsWiredInTheOrderItIsWired(): void
    {
        // When / Then
        static::assertSame(['poll', 'ping'], DeliveryModeNames::of(DeliveryModes::served()->servedDeliveryModes()));
    }

    #[Test]
    public function itFindsAModeByTheNameItGivesItself(): void
    {
        // When / Then
        static::assertInstanceOf(PingDelivery::class, DeliveryModes::served()->named('ping'));
    }

    #[Test]
    public function itRefusesANameNothingIsWiredWith(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The backchannel token delivery mode "push" is not one this provider is wired with.');

        // When
        DeliveryModes::served()->named('push');
    }

    #[Test]
    public function itRefusesAModeWiredTwice(): void
    {
        // Given
        $modes = new ServedDeliveryModes([new PollDelivery(), new PollDelivery()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The backchannel token delivery mode "poll" is wired twice.');

        // When
        $modes->servedDeliveryModes();
    }

    #[Test]
    public function aProviderWiredWithNoneServesNone(): void
    {
        // When / Then
        static::assertSame([], DeliveryModes::none()->servedDeliveryModes());
    }
}
