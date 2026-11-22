<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Ciba\ServedDeliveryModes;
use Beffroi\Oidc\Domain\Ciba\PingDelivery;
use Beffroi\Oidc\Domain\Ciba\PollDelivery;

/**
 * CIBA Core §4
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
