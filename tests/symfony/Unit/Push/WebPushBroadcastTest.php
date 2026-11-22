<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Push;

use App\Messenger\NotificationNotDeliveredException;
use App\Push\PushMessage;
use App\Tests\Symfony\Fixture\BrowsersOfAPerson;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8030, RFC 8291, RFC 8292
 */
final class WebPushBroadcastTest extends TestCase
{
    private BrowsersOfAPerson $browsers;

    protected function setUp(): void
    {
        $this->browsers = new BrowsersOfAPerson();
    }

    #[Test]
    public function aPersonWithNoBrowserIsToldNothingAndNothingFails(): void
    {
        // Given
        $broadcast = $this->browsers->answering([500])->broadcast();

        // When
        $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertSame([], $this->browsers->requests);
    }

    #[Test]
    public function everyBrowserIsPushedAndMarkedAsReached(): void
    {
        // Given
        $this->browsers->subscribed();
        $this->browsers->subscribed('https://push.example/f/Other');
        $broadcast = $this->browsers->broadcast();

        // When
        $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertSame(
            [BrowsersOfAPerson::ENDPOINT, 'https://push.example/f/Other'],
            [$this->browsers->requests[0]->getRequestUrl(), $this->browsers->requests[1]->getRequestUrl()],
        );
        foreach ($this->browsers->subscriptions->findActiveByUser($this->browsers->alice) as $subscription) {
            static::assertEquals($this->browsers->clock->now(), $subscription->lastPushedAt);
        }
    }

    /**
     * RFC 8030 §5.2
     */
    #[Test]
    public function theMessageIsKeptAsLongAsItIsWorthDelivering(): void
    {
        // Given
        $this->browsers->subscribed();
        $broadcast = $this->browsers->broadcast();

        // When
        $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertContains('TTL: 300', $this->browsers->headersOf(0));
    }

    /**
     * RFC 8030 §7.3
     */
    #[Test]
    #[DataProvider('provideGoneStatuses')]
    public function aBrowserThePushServiceSaysIsGoneIsTakenOut(int $status): void
    {
        // Given
        $this->browsers->subscribed();
        $broadcast = $this->browsers->answering([$status])->broadcast();

        // When
        $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertSame([], $this->browsers->subscriptions->findActiveByUser($this->browsers->alice));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideGoneStatuses(): iterable
    {
        yield 'the 404 RFC 8030 asks for' => [404];
        yield 'the 410 the library counts alike' => [410];
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aPushServiceThatDidNotAnswerBringsTheLaneBack(): void
    {
        // Given
        $this->browsers->subscribed();
        $broadcast = $this->browsers->answering([503])->broadcast();

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('No browser of this user was reached');

        // When
        $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());
    }

    #[Test]
    public function oneBrowserReachedIsEnough(): void
    {
        // Given
        $this->browsers->subscribed();
        $this->browsers->subscribed('https://push.example/f/Other');
        $broadcast = $this->browsers->answering([503, 201])->broadcast();

        // When
        $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertCount(2, $this->browsers->requests);
    }

    /**
     * Decision 0048
     */
    #[Test]
    public function aPersonWithNoBrowserIsNotReached(): void
    {
        // When
        $reached = $this->browsers->broadcast()->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertFalse($reached);
    }

    /**
     * Decision 0048
     */
    #[Test]
    public function aPersonWhoseBrowserTookTheMessageIsReached(): void
    {
        // Given
        $this->browsers->subscribed();

        // When
        $reached = $this->browsers->broadcast()->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertTrue($reached);
    }

    /**
     * RFC 8030 §7.3
     */
    #[Test]
    public function aPersonWhoseOnlyBrowserIsGoneIsNotReached(): void
    {
        // Given
        $this->browsers->subscribed();
        $broadcast = $this->browsers->answering([410])->broadcast();

        // When
        $reached = $broadcast->toEveryBrowserOf($this->browsers->alice, $this->message());

        // Then
        static::assertFalse($reached);
    }

    private function message(): PushMessage
    {
        return new PushMessage('Acme', 'Something happened.', 'https://id.acme.example/account', $this->browsers->clock->now()->modify('+300 seconds'));
    }
}
