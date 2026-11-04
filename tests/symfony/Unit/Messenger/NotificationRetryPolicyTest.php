<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use App\Configuration\BackChannelLogoutSection;
use function array_map;
use App\Message\AdvanceKeyLifecycle;
use App\Messenger\NotificationRetryPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;

/**
 * Architecture §5.6
 */
final class NotificationRetryPolicyTest extends TestCase
{
    #[Test]
    public function theWaitGrowsUntilItReachesTheCeiling(): void
    {
        // Given
        $policy = self::policy();

        // When
        $waits = array_map(static fn (int $retry): int => $policy->getWaitingTime(self::afterRetries($retry)), [0, 1, 2, 3, 4, 5]);

        // Then
        static::assertSame([2000, 6000, 18000, 54000, 60000, 60000], $waits);
    }

    #[Test]
    #[DataProvider('provideNumbersBelowTheirFloor')]
    public function aNumberOfTheScheduleBelowTheFloorOfItsNodeIsRefused(int $retries, int $delay, int $multiplier, int $maxDelay, string $message): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new NotificationRetryPolicy($retries, $delay, $multiplier, $maxDelay);
    }

    /**
     * @return iterable<string, array{int, int, int, int, string}>
     */
    public static function provideNumbersBelowTheirFloor(): iterable
    {
        yield 'fewer than no retry' => [
            -1,
            2,
            3,
            60,
            'The "beffroi" configuration key "back_channel_logout.retries" is a number of retries of at least 0, -1 given.',
        ];
        yield 'a first wait of nothing' => [
            6,
            0,
            3,
            60,
            'The "beffroi" configuration key "back_channel_logout.retry_delay" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'waits multiplied by nothing' => [
            6,
            2,
            0,
            60,
            'The "beffroi" configuration key "back_channel_logout.retry_multiplier" is a number of times of at least 1, 0 given.',
        ];
        yield 'a ceiling of nothing' => [
            6,
            2,
            3,
            0,
            'The "beffroi" configuration key "back_channel_logout.retry_max_delay" is a number of seconds of at least 1, 0 given.',
        ];
    }

    #[Test]
    public function aPolicyOfNoRetryIsAPolicy(): void
    {
        // When
        $policy = new NotificationRetryPolicy(0, 1, 1, 1);

        // Then
        static::assertSame(1, $policy->attempts());
    }

    /**
     * Back-Channel Logout 1.0 §2.8
     */
    #[Test]
    #[DataProvider('provideRetryCounts')]
    public function aMessageComesBackWhileThePolicyStillAllowsIt(int $retries, bool $retryable): void
    {
        // Given
        $policy = self::policy();

        // When / Then
        static::assertSame($retryable, $policy->isRetryable(self::afterRetries($retries)));
    }

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function provideRetryCounts(): iterable
    {
        yield 'a send that never came back' => [0, true];
        yield 'the last retry the policy allows' => [5, true];
        yield 'the retries spent' => [6, false];
        yield 'more than the policy ever allowed' => [7, false];
    }

    #[Test]
    #[DataProvider('provideSchedules')]
    public function thePatienceOfTheSenderIsTheSumOfItsWaits(NotificationRetryPolicy $policy, int $waiting): void
    {
        // When / Then
        static::assertSame($waiting, $policy->waiting());
    }

    /**
     * @return iterable<string, array{NotificationRetryPolicy, int}>
     */
    public static function provideSchedules(): iterable
    {
        yield 'the default schedule' => [self::policy(), 2 + 6 + 18 + 54 + 60 + 60];
        yield 'a policy that gives up at once' => [new NotificationRetryPolicy(retries: 0), 0];
        yield 'a constant wait' => [new NotificationRetryPolicy(4, 5, 1, 60), 20];
        yield 'a ceiling reached at the first retry' => [new NotificationRetryPolicy(3, 30, 10, 30), 90];
        yield 'a schedule long enough to overflow a multiplication' => [new NotificationRetryPolicy(40, 2, 3, 60), 2 + 6 + 18 + 54 + (36 * 60)];
    }

    #[Test]
    public function theSendsAreTheRetriesAndTheFirstOne(): void
    {
        // Given
        $policy = self::policy();

        // When / Then
        static::assertSame(7, $policy->attempts());
    }

    private static function policy(): NotificationRetryPolicy
    {
        return new NotificationRetryPolicy(
            BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRIES,
            BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_DELAY,
            BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_MULTIPLIER,
            BackChannelLogoutSection::DEFAULT_BACK_CHANNEL_LOGOUT_RETRY_MAX_DELAY,
        );
    }

    private static function afterRetries(int $retries): Envelope
    {
        return new Envelope(new AdvanceKeyLifecycle(), $retries === 0 ? [] : [new RedeliveryStamp($retries)]);
    }
}
