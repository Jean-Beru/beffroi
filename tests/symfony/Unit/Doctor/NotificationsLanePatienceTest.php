<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctor;

use App\Doctor\Finding;
use App\Doctor\NotificationsLanePatience;
use App\Message\Notification;
use function sprintf;
use App\Messenger\NotificationRetryPolicy;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use DateInterval;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\Messenger\Retry\MultiplierRetryStrategy;
use Symfony\Component\Messenger\Retry\RetryStrategyInterface;
use Symfony\Component\Messenger\Transport\Sender\SenderInterface;
use Symfony\Component\Messenger\Transport\Sender\SendersLocator;

final class NotificationsLanePatienceTest extends TestCase
{
    #[Test]
    public function aLogoutTokenRoutedNowhereIsRed(): void
    {
        // Given
        $check = self::check([], []);

        // When
        $finding = $check->finding();

        // Then
        static::assertFalse($finding->green);
        static::assertStringContainsString('Nothing carries a logout token', self::firstLine($finding));
    }

    #[Test]
    public function aLaneNothingRetriesIsRedAndSaysOneFailedSendIsAClientNeverTold(): void
    {
        // Given
        $check = self::check(['a_lane'], []);

        // When
        $finding = $check->finding();

        // Then
        static::assertFalse($finding->green);
        static::assertSame(
            'This deployment sends a logout token to the transport "a_lane" and nothing retries it there, so one failed send is a client never told, and the 4 minutes a token stays verifiable are waited by nobody.',
            self::firstLine($finding),
        );
    }

    #[Test]
    public function aLaneThatNeverGivesUpIsRedAndSaysSoInWords(): void
    {
        // Given
        $strategy = static::createStub(RetryStrategyInterface::class);
        $strategy->method('isRetryable')->willReturn(true);
        $strategy->method('getWaitingTime')->willReturn(1000);
        $check = self::check(['a_lane'], ['a_lane' => $strategy]);

        // When
        $finding = $check->finding();

        // Then
        static::assertFalse($finding->green);
        static::assertStringContainsString('for as long as it takes', self::firstLine($finding));
    }

    #[Test]
    public function theLineCarriesHowLongItTriesAndHowLongWhatItSendsLasts(): void
    {
        // Given
        $check = self::check(['a_lane'], ['a_lane' => self::retriedFor(2, 60_000)]);

        // When
        $finding = $check->finding();

        // Then
        static::assertStringContainsString(
            'retries a logout token on the transport "a_lane" for 2 minutes. One stops being verifiable after 4 minutes',
            self::firstLine($finding),
        );
    }

    /**
     * @param int $delay in milliseconds
     */
    #[Test]
    #[DataProvider('provideSchedules')]
    public function aLengthOfTimeIsSaidAsAReaderCountsIt(int $retries, int $delay, string $said): void
    {
        // Given
        $check = self::check(['a_lane'], ['a_lane' => self::retriedFor($retries, $delay)]);

        // When
        $finding = $check->finding();

        // Then
        static::assertStringContainsString(sprintf('for %s.', $said), self::firstLine($finding));
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function provideSchedules(): iterable
    {
        yield 'one second' => [1, 1000, '1 second'];
        yield 'seconds' => [45, 1000, '45 seconds'];
        yield 'one minute' => [60, 1000, '1 minute'];
        yield 'minutes' => [2, 60_000, '2 minutes'];
        yield 'minutes and one second' => [121, 1000, '2 minutes 1 second'];
        yield 'minutes and seconds' => [3, 45_000, '2 minutes 15 seconds'];
    }

    #[Test]
    public function aSecondInstanceOfThePolicyIsRed(): void
    {
        // Given
        $check = self::check(['a_lane'], ['a_lane' => new NotificationRetryPolicy()]);

        // When
        $finding = $check->finding();

        // Then
        static::assertFalse($finding->green);
        static::assertStringContainsString(NotificationRetryPolicy::class, self::firstLine($finding));
    }

    #[Test]
    public function oneLaneOfTwoBeingWrongNamesThatOneAlone(): void
    {
        // Given
        $policy = new NotificationRetryPolicy();
        $check = new NotificationsLanePatience(
            self::senders(['on_the_policy', 'on_its_own']),
            self::strategies([
                'on_the_policy' => $policy,
                'on_its_own' => self::retriedFor(2, 60_000),
            ]),
            $policy,
            self::window(),
        );

        // When
        $finding = $check->finding();

        // Then
        static::assertFalse($finding->green);
        static::assertStringContainsString('"on_its_own"', self::firstLine($finding));
        static::assertStringNotContainsString('"on_the_policy"', self::firstLine($finding));
    }

    #[Test]
    public function twoLanesBothOnThePolicyAreGreen(): void
    {
        // Given
        $policy = new NotificationRetryPolicy();
        $check = new NotificationsLanePatience(
            self::senders(['one', 'another']),
            self::strategies(['one' => $policy, 'another' => $policy]),
            $policy,
            self::window(),
        );

        // When
        $finding = $check->finding();

        // Then
        static::assertTrue($finding->green);
        static::assertStringContainsString('A logout token is retried on "one", "another" for', self::firstLine($finding));
    }

    #[Test]
    public function aRoutingTheContainerCannotAnswerIsRedAndNamesWhy(): void
    {
        // Given
        $check = new NotificationsLanePatience(
            new SendersLocator([Notification::class => ['a_lane']], new ServiceLocator([])),
            self::strategies([]),
            new NotificationRetryPolicy(),
            self::window(),
        );

        // When
        $finding = $check->finding();

        // Then
        static::assertFalse($finding->green);
        static::assertSame(
            'What carries a logout token cannot be read from the container: Invalid senders configuration: sender "a_lane" is not in the senders locator.',
            self::firstLine($finding),
        );
    }

    #[Test]
    public function thePolicyPublishesThreeMinutesAndTwentySecondsOfRetries(): void
    {
        // When / Then
        static::assertSame(200, new NotificationRetryPolicy()->waiting());
    }

    private static function firstLine(Finding $finding): string
    {
        return $finding->lines[0] ?? static::fail('The finding says nothing.');
    }

    /**
     * @param list<string> $lanes
     * @param array<string, RetryStrategyInterface> $strategies by transport
     */
    private static function check(array $lanes, array $strategies): NotificationsLanePatience
    {
        return new NotificationsLanePatience(
            self::senders($lanes),
            self::strategies($strategies),
            new NotificationRetryPolicy(),
            self::window(),
        );
    }

    private static function retriedFor(int $retries, int $delay): RetryStrategyInterface
    {
        return new MultiplierRetryStrategy($retries, $delay, 1, $delay, 0);
    }

    private static function window(): LogoutTokenDeliveryInterface
    {
        $window = static::createStub(LogoutTokenDeliveryInterface::class);
        $window->method('deliveryBudget')->willReturn(new DateInterval('PT4M'));

        return $window;
    }

    /**
     * @param list<string> $lanes
     */
    private static function senders(array $lanes): SendersLocator
    {
        $senders = [];
        foreach ($lanes as $lane) {
            $senders[$lane] = static fn (): SenderInterface => static::createStub(SenderInterface::class);
        }

        return new SendersLocator($lanes === [] ? [] : [Notification::class => $lanes], new ServiceLocator($senders));
    }

    /**
     * @param array<string, RetryStrategyInterface> $strategies
     */
    private static function strategies(array $strategies): ContainerInterface
    {
        $factories = [];
        foreach ($strategies as $lane => $strategy) {
            $factories[$lane] = static fn (): RetryStrategyInterface => $strategy;
        }

        return new ServiceLocator($factories);
    }
}
