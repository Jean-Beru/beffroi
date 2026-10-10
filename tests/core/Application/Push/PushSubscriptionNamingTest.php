<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Push;

use Beffroi\Core\Application\Push\PushSubscriptionNaming;
use Beffroi\Core\Bridge\InMemory\InMemoryPushSubscriptionRepository;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2: the person whose browsers may be pushed to names one of them from the page of their
 * account, and names it again.
 */
final class PushSubscriptionNamingTest extends TestCase
{
    private const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    private User $alice;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user(Fixtures::tenant());
    }

    #[Test]
    public function theNameTheHolderWroteIsKept(): void
    {
        // Given
        $subscriptions = new InMemoryPushSubscriptionRepository();
        $subscription = $this->subscribed($subscriptions);

        // When
        new PushSubscriptionNaming($subscriptions)->rename($subscription, 'Alice at home');

        // Then
        static::assertSame('Alice at home', $subscriptions->find($subscription->id)?->label);
    }

    /**
     * A name that is the one it already holds changes nothing and writes nothing: a line somebody tabbed
     * out of is not a row to save.
     */
    #[Test]
    public function aNameItAlreadyHoldsWritesNothing(): void
    {
        // Given
        $subscriptions = $this->createMock(PushSubscriptionRepositoryInterface::class);
        $subscriptions->expects(static::never())->method('save');

        // When
        new PushSubscriptionNaming($subscriptions)->rename($this->subscription(), 'Alice at the counter');
    }

    /**
     * What a browser may be called is the rule of the row that holds it, and a name it would refuse is
     * never written.
     */
    #[Test]
    public function aNameABrowserDoesNotHoldIsRefusedAndWritesNothing(): void
    {
        // Given
        $subscriptions = new InMemoryPushSubscriptionRepository();
        $subscription = $this->subscribed($subscriptions);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The name of a browser is 1 to 255 characters long.');

        // When
        new PushSubscriptionNaming($subscriptions)->rename($subscription, '');
    }

    private function subscribed(InMemoryPushSubscriptionRepository $subscriptions): PushSubscription
    {
        $subscription = $this->subscription();
        $subscriptions->save($subscription);

        return $subscription;
    }

    private function subscription(): PushSubscription
    {
        return new PushSubscription(
            Uuid::v7(),
            $this->alice,
            self::ENDPOINT,
            self::PUBLIC_KEY,
            self::AUTH_SECRET,
            'the-key',
            'Alice at the counter',
            Fixtures::now(),
        );
    }
}
