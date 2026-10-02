<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Messenger;

use Beffroi\Bundle\Configuration\BackChannelLogoutSection;
use function array_map;
use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Messenger\NotificationRetryPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;

/**
 * How long the provider goes on trying to hand a notification to the third party it is addressed to
 * (architecture §5.6, issue #155): the schedule the transport of the application follows, and the one a
 * signing key is held back for while a logout token it signed may still be on its way.
 */
final class NotificationRetryPolicyTest extends TestCase
{
    /**
     * Two seconds, then three times as long each time, one minute at most.
     */
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

    /**
     * Back-Channel Logout 1.0 §2.8: beyond the schedule the client is not restarting, it is down, and the
     * message is given up on instead of coming back for ever.
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

    /**
     * What a retirement window reads: the whole schedule at once, in seconds.
     */
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

    /**
     * The first send is one attempt, and each retry is another.
     */
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
