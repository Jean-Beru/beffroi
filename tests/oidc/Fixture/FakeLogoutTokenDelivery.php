<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use DateInterval;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;

/**
 * A delivery whose patience is the one given. The real one, LogoutTokenDeliveryBudget of the bundle,
 * reads it from the retries of the transport and the timeout of one send.
 */
final readonly class FakeLogoutTokenDelivery implements LogoutTokenDeliveryInterface
{
    public function __construct(
        private DateInterval $budget,
    ) {
    }

    public function deliveryBudget(): DateInterval
    {
        return $this->budget;
    }
}
