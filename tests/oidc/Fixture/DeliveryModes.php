<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Application\Ciba\ServedDeliveryModes;
use Heidi\Oidc\Domain\Ciba\PingDelivery;
use Heidi\Oidc\Domain\Ciba\PollDelivery;

/**
 * The ways of telling a client that a backchannel request was answered, as the tests wire them (CIBA
 * Core §4): both of the ones the provider serves, and a wiring with none for what a provider that serves
 * no such flow announces and accepts.
 */
final readonly class DeliveryModes
{
    public static function served(): ServedDeliveryModes
    {
        return new ServedDeliveryModes([new PollDelivery(), new PingDelivery()]);
    }

    public static function pollOnly(): ServedDeliveryModes
    {
        return new ServedDeliveryModes([new PollDelivery()]);
    }

    public static function none(): ServedDeliveryModes
    {
        return new ServedDeliveryModes([]);
    }
}
