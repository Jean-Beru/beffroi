<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\Registration\RegisteredClientRemoval;
use Heidi\Oidc\Application\Client\Registration\UnusedClientRemoval;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Event\RegisteredClientDeleted;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Tests\Fixture\RegistrationPolicies;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0009: a client nobody uses any more is deleted, after the durations its tenant names. The
 * durations here are the ones the policy of the tests names, and time is the mocked clock: a client is there
 * one instant before and gone one instant after.
 */
final class UnusedClientRemovalTest extends TestCase
{
    /**
     * What the policy of the tests keeps a client that was used for, and one that never was.
     */
    private const string UNUSED_FOR = '+90 days';

    private const string NEVER_USED_FOR = '+7 days';

    private Tenant $tenant;

    private InMemoryClientStore $clients;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientStore();
        $this->events = new RecordingEventDispatcher();
    }

    #[Test]
    public function aClientUsedWithinTheDurationItsPolicyNamesIsThere(): void
    {
        // Given
        $this->register('used-lately', lastUsedAt: Fixtures::now());

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::UNUSED_FOR)->modify('-1 second'));

        // Then
        static::assertSame([], $removed);
    }

    #[Test]
    public function aClientNobodyUsedForLongerThanItsPolicyNamesIsGone(): void
    {
        // Given
        $this->register('used-long-ago', lastUsedAt: Fixtures::now());

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::UNUSED_FOR)->modify('+1 second'));

        // Then
        static::assertSame(['used-long-ago'], $removed);
        static::assertNull($this->clients->findRecord($this->tenant, 'used-long-ago'));
    }

    /**
     * A client that was never used holds nothing at all, so it goes on the shorter of the two durations.
     */
    #[Test]
    public function aClientNobodyEverUsedGoesOnTheShorterDuration(): void
    {
        // Given
        $this->register('never-used');

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'));

        // Then
        static::assertSame(['never-used'], $removed);
    }

    #[Test]
    public function aClientNobodyEverUsedIsThereUntilThen(): void
    {
        // Given
        $this->register('never-used');

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('-1 second'));

        // Then
        static::assertSame([], $removed);
    }

    /**
     * One event says a client is gone, whichever way it went.
     */
    #[Test]
    public function eachClientRemovedIsAnnouncedByTheOneEventAClientGoingAwayEmits(): void
    {
        // Given
        $this->register('never-used');

        // When
        $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'));

        // Then
        $events = $this->events->of(RegisteredClientDeleted::class);
        static::assertCount(1, $events);
        static::assertSame('never-used', $events[0]->clientId);
    }

    /**
     * A step that locks a table on a large deployment is an outage, so a run removes at most what it is
     * bounded to and the next one takes the rest.
     */
    #[Test]
    public function aRunRemovesAtMostWhatItIsBoundedTo(): void
    {
        // Given
        for ($drawn = 0; $drawn < 5; $drawn++) {
            $this->register(sprintf('never-used-%d', $drawn));
        }

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify(self::NEVER_USED_FOR)->modify('+1 second'), 2);

        // Then
        static::assertCount(2, $removed);
        static::assertCount(3, $this->clients->records);
    }

    /**
     * Decision 0009: a tenant with no registration policy has no client that registered itself, so there is
     * nothing to keep and nothing to drop.
     */
    #[Test]
    public function aTenantThatRegistersNobodyDropsNothing(): void
    {
        // Given
        $this->register('never-used');

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify('+1 year'), policies: RegistrationPolicies::closed());

        // Then
        static::assertSame([], $removed);
        static::assertCount(1, $this->clients->records);
    }

    /**
     * The clients of one tenant are no business of another.
     */
    #[Test]
    public function aClientOfAnotherTenantIsNotDropped(): void
    {
        // Given
        $this->register('never-used', tenant: Fixtures::tenant('other', 'https://id.other.example'));

        // When
        $removed = $this->removeUnusedAt(Fixtures::now()->modify('+1 year'));

        // Then
        static::assertSame([], $removed);
    }

    private function register(string $clientId, ?DateTimeImmutable $lastUsedAt = null, ?Tenant $tenant = null): void
    {
        $record = new ClientRecord(
            Uuid::v7(),
            $tenant ?? $this->tenant,
            $clientId,
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
            DrawnSecret::digestOf(Secrets::draw()),
            Fixtures::now(),
        );
        if ($lastUsedAt !== null) {
            $record->recordUse($lastUsedAt);
        }
        $this->clients->save($record);
    }

    /**
     * @return list<string>
     */
    private function removeUnusedAt(
        DateTimeImmutable $now,
        int $perRun = UnusedClientRemoval::PER_RUN,
        ?ClientRegistrationPolicyInterface $policies = null,
    ): array {
        return new UnusedClientRemoval(
            [$this->clients],
            $policies ?? RegistrationPolicies::controlled(),
            new RegisteredClientRemoval($this->clients, $this->events),
            new MockClock($now),
            $perRun,
        )->removeUnused($this->tenant, Fixtures::context($now));
    }
}
