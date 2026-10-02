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
 * CIBA Core §4: the modes the wiring gave the provider, in the order they are wired, read by the document
 * that announces them and by the registration that names one.
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

    /**
     * A name nothing is wired with is refused where a registration is read, at boot.
     */
    #[Test]
    public function itRefusesANameNothingIsWiredWith(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The backchannel token delivery mode "push" is not one this provider is wired with.');

        // When
        DeliveryModes::served()->named('push');
    }

    /**
     * Two places that must agree are one place: a mode wired twice is a wiring that does not hold.
     */
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

    /**
     * A deployment that serves no such flow serves no mode, which is what the document then announces.
     */
    #[Test]
    public function aProviderWiredWithNoneServesNone(): void
    {
        // When / Then
        static::assertSame([], DeliveryModes::none()->servedDeliveryModes());
    }
}
