<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use DateInterval;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;

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
