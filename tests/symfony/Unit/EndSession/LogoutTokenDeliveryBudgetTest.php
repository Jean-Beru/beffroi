<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\EndSession;

use App\Http\Timeout;
use App\Configuration\BackChannelLogoutSection;
use DateInterval;
use App\EndSession\LogoutTokenDeliveryBudget;
use App\Http\LogoutTokenSender;
use App\Messenger\NotificationRetryPolicy;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Back-Channel Logout 1.0 §2.5, RFC 8417 §2.2
 */
final class LogoutTokenDeliveryBudgetTest extends TestCase
{
    #[Test]
    public function aLogoutTokenLivesTheWaitsOfItsLaneAndTheTimeoutOfEverySend(): void
    {
        // Given
        $budget = new LogoutTokenDeliveryBudget(
            new NotificationRetryPolicy(
                BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRIES,
                BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_DELAY,
                BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_MULTIPLIER,
                BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_MAX_DELAY,
            ),
            $this->sender(BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_TIMEOUT),
        );

        // When / Then
        static::assertEquals(new DateInterval('PT235S'), $budget->deliveryBudget());
    }

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
        return new LogoutTokenSender(static::createStub(HttpClientInterface::class), new Timeout($timeout));
    }
}
