<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\PushSubscriptionQuestion;
use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class PushSubscriptionQuestionTest extends TestCase
{
    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    #[Test]
    public function aQuestionThatAsksNothingAdmitsEverySubscription(): void
    {
        // When / Then
        static::assertTrue(new PushSubscriptionQuestion()->admits(self::subscription(Fixtures::now())));
    }

    #[Test]
    #[DataProvider('provideSubscriptions')]
    public function theDaysOfSubscriptionAdmitWhatSubscribedOnThem(string $subscribedAt, bool $admitted): void
    {
        // Given
        $question = new PushSubscriptionQuestion(subscribed: Period::ofDays(Fixtures::now(), Fixtures::now()));

        // When / Then
        static::assertSame($admitted, $question->admits(self::subscription(Fixtures::now()->modify($subscribedAt))));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideSubscriptions(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    #[Test]
    #[DataProvider('providePushes')]
    public function theDaysOfTheLastPushAdmitWhatWasLastToldOnThem(string $pushedAt, bool $admitted): void
    {
        // Given
        $question = new PushSubscriptionQuestion(pushed: Period::ofDays(Fixtures::now(), Fixtures::now()));
        $subscription = self::subscription(Fixtures::now()->modify('-1 month'));
        $subscription->markPushed(Fixtures::now()->modify($pushedAt));

        // When / Then
        static::assertSame($admitted, $question->admits($subscription));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function providePushes(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    #[Test]
    public function aSubscriptionNothingWasPushedToIsInNoPeriodOfPushes(): void
    {
        // Given
        $question = new PushSubscriptionQuestion(pushed: Period::ofDays(null, Fixtures::now()));

        // When / Then
        static::assertFalse($question->admits(self::subscription(Fixtures::now())));
    }

    private static function subscription(DateTimeImmutable $createdAt): PushSubscription
    {
        return new PushSubscription(
            Uuid::v7(),
            Fixtures::user(),
            'https://push.example/f/AbCdEf',
            self::PUBLIC_KEY,
            self::AUTH_SECRET,
            'the-key',
            'Alice at the counter',
            $createdAt,
        );
    }
}
