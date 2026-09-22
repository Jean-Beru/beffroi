<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\EndSession;

use DateInterval;
use Heidi\Bundle\EndSession\LogoutTokenDeliveryBudget;
use Heidi\Bundle\HeidiBundle;
use Heidi\Bundle\Http\LogoutTokenSender;
use Heidi\Bundle\Messenger\NotificationRetryPolicy;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Back-Channel Logout 1.0 §2.5 and issue #155: how long a logout token stays on its way, which is what a
 * signing key is held back for since the token carries no "exp" of its own (RFC 8417 §2.2).
 */
final class LogoutTokenDeliveryBudgetTest extends TestCase
{
    /**
     * The waits of the schedule, and the seconds each of the seven sends is given before it is a failure:
     * 200 plus 35 with the values the bundle defaults to.
     */
    #[Test]
    public function aLogoutTokenLivesTheWaitsOfItsLaneAndTheTimeoutOfEverySend(): void
    {
        // Given
        $budget = new LogoutTokenDeliveryBudget(
            new NotificationRetryPolicy(
                HeidiBundle::DEFAULT_BACK_CHANNEL_LOGOUT_RETRIES,
                HeidiBundle::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_DELAY,
                HeidiBundle::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_MULTIPLIER,
                HeidiBundle::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_MAX_DELAY,
            ),
            $this->sender(HeidiBundle::DEFAULT_BACK_CHANNEL_LOGOUT_TIMEOUT),
        );

        // When / Then
        static::assertEquals(new DateInterval('PT235S'), $budget->deliveryBudget());
    }

    /**
     * A timeout of a fraction of a second is still a second of the window: what holds a key back is
     * rounded up, never down.
     */
    #[Test]
    public function aTimeoutOfAFractionOfASecondCountsAsAWholeOne(): void
    {
        // Given
        $budget = new LogoutTokenDeliveryBudget(new NotificationRetryPolicy(retries: 0), $this->sender(0.5));

        // When / Then
        static::assertEquals(new DateInterval('PT1S'), $budget->deliveryBudget());
    }

    private function sender(float $timeout): LogoutTokenSender
    {
        return new LogoutTokenSender(static::createStub(HttpClientInterface::class), $timeout);
    }
}
