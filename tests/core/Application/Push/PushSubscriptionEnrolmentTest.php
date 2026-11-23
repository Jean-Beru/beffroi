<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Push;

use Beffroi\Core\Application\Push\PushSubscriptionEnrolment;
use Beffroi\Core\Application\Push\PushSubscriptionRevocation;
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
 * RFC 8292 §3.2, Push API §3.4
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
            new PushSubscriptionRevocation($this->subscriptions, $this->clock),
        );
    }

    /**
     * §3.2
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

    #[Test]
    public function aBrowserBeyondTheMostAPersonKeepsTakesOutTheOldest(): void
    {
        // Given
        $this->activeKey();
        $oldest = $this->enrolOneMinuteApart(PushSubscriptionEnrolment::MOST_BROWSERS)[0];

        // When
        $this->clock->modify('+1 minute');
        $this->enrol(endpoint: 'https://push.example/f/latest');

        // Then
        static::assertCount(PushSubscriptionEnrolment::MOST_BROWSERS, $this->subscriptions->findActiveByUser($this->alice));
        static::assertTrue($oldest->isRevoked());
    }

    #[Test]
    public function theBrowserThatSubscribesAgainIsNotTheOneTakenOut(): void
    {
        // Given
        $this->activeKey();
        [$oldest, $next] = $this->enrolOneMinuteApart(PushSubscriptionEnrolment::MOST_BROWSERS + 1);

        // When
        $this->clock->modify('+1 minute');
        $again = $this->enrol(endpoint: $oldest->endpoint);

        // Then
        static::assertFalse($again->isRevoked());
        static::assertTrue($next->isRevoked());
    }

    /**
     * Decision 0002
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
     * §3.2
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

    /**
     * @return list<PushSubscription> in the order they were enrolled
     */
    private function enrolOneMinuteApart(int $browsers): array
    {
        $enrolled = [];
        for ($browser = 1; $browser <= $browsers; $browser++) {
            $this->clock->modify('+1 minute');
            $enrolled[] = $this->enrol(endpoint: 'https://push.example/f/' . $browser);
        }

        return $enrolled;
    }

    private function enrol(?string $label = 'Alice at the counter', string $endpoint = self::ENDPOINT): PushSubscription
    {
        return $this->enrolment->enrol(
            $this->alice,
            Algorithms::vapid(),
            $endpoint,
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
