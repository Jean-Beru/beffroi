<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Push;

use Beffroi\Core\Application\Push\PushSubscriptionEnrolment;
use Beffroi\Core\Bridge\InMemory\InMemoryPushSubscriptionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 8292 §3.2, Push API §3.4: a browser says where it can be pushed to, and what it hands over is
 * recorded against the application server key it was handed.
 */
final class PushSubscriptionEnrolmentTest extends TestCase
{
    private const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    private Tenant $tenant;

    private User $alice;

    private MockClock $clock;

    private InMemoryTenantKeyRepository $keys;

    private InMemoryPushSubscriptionRepository $subscriptions;

    private PushSubscriptionEnrolment $enrolment;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->clock = new MockClock('2026-09-28T09:00:00+00:00');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->subscriptions = new InMemoryPushSubscriptionRepository();
        $this->enrolment = new PushSubscriptionEnrolment(
            $this->subscriptions,
            new SealedKeyProvider($this->keys, Keys::opened()),
            new SymfonyUuidGenerator(),
            $this->clock,
        );
    }

    /**
     * §3.2: what the browser handed over, bound to the key it was handed.
     */
    #[Test]
    public function itRecordsWhatTheBrowserHandedOverAgainstTheActiveKey(): void
    {
        // Given
        $key = $this->activeKey();

        // When
        $subscription = $this->enrol();

        // Then
        static::assertSame(self::ENDPOINT, $subscription->endpoint);
        static::assertSame(self::PUBLIC_KEY, $subscription->publicKey);
        static::assertSame(self::AUTH_SECRET, $subscription->authSecret);
        static::assertSame($key->kid, $subscription->applicationServerKid);
        static::assertCount(1, $this->subscriptions->findActiveByUser($this->alice));
    }

    /**
     * A browser that subscribes again hands back the endpoint it already had: one browser, one row.
     */
    #[Test]
    public function aBrowserThatSubscribesAgainKeepsItsRow(): void
    {
        // Given
        $this->activeKey();
        $first = $this->enrol();

        // When
        $this->clock->modify('+1 day');
        $again = $this->enrol(label: 'Alice at home');

        // Then
        static::assertTrue($first->id->equals($again->id));
        static::assertEquals($first->createdAt, $again->createdAt);
        static::assertSame('Alice at home', $again->label);
        static::assertCount(1, $this->subscriptions->findActiveByUser($this->alice));
    }

    /**
     * A browser the user had taken out comes back in use when it subscribes again, and does not stay
     * revoked beside itself.
     */
    #[Test]
    public function aBrowserThatWasTakenOutComesBackWhenItSubscribesAgain(): void
    {
        // Given
        $this->activeKey();
        $this->enrol()->revoke($this->clock->now());

        // When
        $this->enrol();

        // Then
        static::assertCount(1, $this->subscriptions->findActiveByUser($this->alice));
    }

    /**
     * Decision 0002: the browsers of one user are theirs, and a browser of somebody else is none of them.
     */
    #[Test]
    public function theBrowsersOfOneUserAreNotTheBrowsersOfAnother(): void
    {
        // Given
        $this->activeKey();
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->enrol();

        // When
        $waiting = $this->subscriptions->findActiveByUser($bob);

        // Then
        static::assertSame([], $waiting);
    }

    /**
     * A browser is recognised by its endpoint among the browsers of that user, so an endpoint of
     * somebody else is one this user has never subscribed.
     */
    #[Test]
    public function anEndpointOfSomebodyElseIsNoBrowserOfThisUser(): void
    {
        // Given
        $this->activeKey();
        $this->enrol();

        // When
        $found = $this->subscriptions->findByEndpoint(Fixtures::user($this->tenant, 'bob', 'bob-subject'), self::ENDPOINT);

        // Then
        static::assertNull($found);
    }

    /**
     * §3.2: a browser is handed a key before it subscribes, so a tenant that has none has nothing for a
     * subscription to be recorded against.
     */
    #[Test]
    public function aTenantWithoutAnActiveKeyRecordsNothing(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('has no active VAPID key to hand out');

        // When
        $this->enrol();
    }

    private function enrol(?string $label = 'Alice at the counter'): PushSubscription
    {
        return $this->enrolment->enrol(
            $this->alice,
            Algorithms::vapid(),
            self::ENDPOINT,
            self::PUBLIC_KEY,
            self::AUTH_SECRET,
            $label,
        );
    }

    private function activeKey(): TenantKey
    {
        $pair = Keys::applicationServerPair();
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            Algorithms::vapid(),
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            $this->clock->now(),
            $this->clock->now(),
        );
        $key->activate($this->clock->now());
        $this->keys->save($key);

        return $key;
    }
}
