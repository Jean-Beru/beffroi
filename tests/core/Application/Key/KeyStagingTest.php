<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use DateInterval;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Domain\Event\TenantKeyRotated;
use Beffroi\Core\Domain\Event\TenantKeyStaged;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeyLifecycle;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * OIDC Core §10.1.1, Architecture §3.3
 */
final class KeyStagingTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $repository;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private KeyStaging $staging;

    private KeyTakeOver $takeOver;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-15T14:00:00+00:00');
        $this->context = RequestContext::unknown($this->clock->now());
        $lifecycle = new KeyLifecycle($this->clock);
        $this->repository = $lifecycle->keys;
        $this->events = $lifecycle->events;
        $this->staging = $lifecycle->staging;
        $this->takeOver = $lifecycle->takeOver;
    }

    #[Test]
    public function stagingPublishesAKeyThatDoesNotSign(): void
    {
        // Given
        $first = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+30 days');

        // When
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(KeyStatus::Staged, $staged->status);
        static::assertEquals($this->clock->now(), $staged->createdAt);
        static::assertSame([$first, $staged], $this->repository->findInService($this->tenant));
        static::assertSame($first, $this->repository->findActive($this->tenant, Algorithms::rs256()));
    }

    #[Test]
    public function stagingDatesTheActivationAfterTheStagingDelay(): void
    {
        // When
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertEquals($this->clock->now()->add(new DateInterval(KeyLifecycle::STAGING_DELAY)), $staged->activationDueAt);
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    #[DataProvider('provideFamilies')]
    public function stagingDatesTheActivationAfterTheStagingDelayOfItsFamily(KeyAlgorithmInterface $algorithm, string $delay): void
    {
        // Given
        $staging = new KeyLifecycle($this->clock, generator: new JwtLibraryKeyPairGenerator(Algorithms::everyUse()), families: [
            Algorithms::es256()->name() => new RotationSchedule(new DateInterval('P7D'), new DateInterval('P365D')),
        ])->staging;

        // When
        $staged = $staging->stage($this->tenant, $algorithm, $this->context);

        // Then
        static::assertEquals($this->clock->now()->add(new DateInterval($delay)), $staged->activationDueAt);
    }

    /**
     * @return iterable<string, array{KeyAlgorithmInterface, string}>
     */
    public static function provideFamilies(): iterable
    {
        yield 'a family with a window of its own' => [Algorithms::es256(), 'P7D'];
        yield 'every other family' => [Algorithms::edDsa(), KeyLifecycle::STAGING_DELAY];
    }

    #[Test]
    public function stagingSealsThePrivateKeyForTheTenant(): void
    {
        // When
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(Keys::pair()->privateJwk, Keys::sealer()->unseal($this->tenant, $staged->sealedPrivateJwk));
    }

    #[Test]
    public function stagingAnnouncesTheKey(): void
    {
        // When
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        [$event] = $this->events->of(TenantKeyStaged::class);
        static::assertSame($staged, $event->staged);
        static::assertSame($this->tenant, $event->tenant);
        static::assertSame($this->context, $event->context);
        static::assertSame([], $this->events->of(TenantKeyRotated::class));
    }

    #[Test]
    public function aKeyStagedToTakeOverAtOnceIsDueAtOnce(): void
    {
        // When
        $staged = $this->staging->stageDueAtOnce($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertEquals($this->clock->now(), $staged->activationDueAt);
    }

    #[Test]
    public function aKeyStagedToTakeOverAtOnceIsPublishedDoingNothing(): void
    {
        // When
        $staged = $this->staging->stageDueAtOnce($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(KeyStatus::Staged, $staged->status);
        static::assertSame([$staged], $this->repository->findInService($this->tenant));
        static::assertSame($staged, $this->events->of(TenantKeyStaged::class)[0]->staged);
    }
}
