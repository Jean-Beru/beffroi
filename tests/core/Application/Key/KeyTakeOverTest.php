<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use DateInterval;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Event\TenantKeyRetired;
use Beffroi\Core\Domain\Event\TenantKeyRotated;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\RetirementReason;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FixedLifetimeArtifact;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeyLifecycle;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * The second step of the life of a key (OIDC Core §10.1.1, architecture §3.3): the staged key signs from
 * now on, the one it takes over from stays published while a JWS it signed can be alive, and a compromised
 * key leaves the JWK Set in the same call.
 */
final class KeyTakeOverTest extends TestCase
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
    public function theFirstRotationActivatesAKeyAtOnceAndRetiresNothing(): void
    {
        // When
        $first = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(Keys::pair()->kid, $first->kid);
        static::assertTrue($first->isActive());
        static::assertEquals($this->clock->now(), $first->activatedAt);
        static::assertSame($first, $this->repository->findActive($this->tenant, Algorithms::rs256()));
        static::assertNull($this->events->of(TenantKeyRotated::class)[0]->retiring);
    }

    #[Test]
    public function activatingAStagedKeyMakesItSign(): void
    {
        // Given
        $this->firstRotation();
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $activated = $this->takeOver->activate($this->tenant, $staged->kid, $this->context);

        // Then
        static::assertSame($staged, $activated);
        static::assertTrue($activated->isActive());
        static::assertEquals($this->clock->now(), $activated->activatedAt);
        static::assertSame($activated, $this->repository->findActive($this->tenant, Algorithms::rs256()));
        static::assertSame(
            Keys::otherPair()->privateJwk,
            new SealedKeyProvider($this->repository, Keys::sealer())->activeKey($this->tenant, Algorithms::rs256())->privateJwk,
        );
    }

    /**
     * The timed step of the staging window: a key past its activation date is activated, and not before.
     */
    #[Test]
    public function activateDueActivatesAKeyPastItsActivationDate(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $activated = $this->takeOver->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([$staged], $activated);
        static::assertTrue($staged->isActive());
        static::assertEquals($this->clock->now(), $staged->activatedAt);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame($staged, $this->repository->findActive($this->tenant, Algorithms::rs256()));
    }

    #[Test]
    public function activateDueLeavesAKeyInsideItsStagingWindow(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+5 minutes 59 seconds');
        $savesBefore = $this->repository->saves;

        // When
        $activated = $this->takeOver->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $activated);
        static::assertSame(KeyStatus::Staged, $staged->status);
        static::assertSame($savesBefore, $this->repository->saves);
        static::assertSame($first, $this->repository->findActive($this->tenant, Algorithms::rs256()));
    }

    /**
     * Two keys due in the same tick: both are activated in creation order, the last one signs.
     */
    #[Test]
    public function activateDueActivatesEveryDueKeyTheLastOneSigning(): void
    {
        // Given
        $first = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 second');
        $second = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $activated = $this->takeOver->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([$first, $second], $activated);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame($second, $this->repository->findActive($this->tenant, Algorithms::rs256()));
    }

    #[Test]
    public function activateDueAnnouncesTheRotation(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 hour');

        // When
        $this->takeOver->activateDue($this->tenant, $this->context);

        // Then
        $event = $this->events->of(TenantKeyRotated::class)[1];
        static::assertSame($staged, $event->activated);
        static::assertSame($first, $event->retiring);
        static::assertSame($this->context, $event->context);
    }

    #[Test]
    public function activateDueDoesNothingWithoutAStagedKey(): void
    {
        // Given
        $this->firstRotation();
        $savesBefore = $this->repository->saves;

        // When
        $activated = $this->takeOver->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $activated);
        static::assertSame($savesBefore, $this->repository->saves);
        static::assertCount(1, $this->events->of(TenantKeyRotated::class));
    }

    /**
     * The retirement window opens: the previous key is due once the longest JWS the tenant issues, signed
     * a moment before the activation, has expired (RetirementWindow).
     */
    #[Test]
    public function activatingAStagedKeyStartsRetiringTheActiveOne(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $this->takeOver->activate($this->tenant, $staged->kid, $this->context);

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertEquals($this->clock->now()->add(new DateInterval(KeyLifecycle::LONGEST_LIFETIME)), $first->retirementDueAt);
        static::assertSame([$first, $staged], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function activatingTheActiveKeyFails(): void
    {
        // Given
        $first = $this->firstRotation();

        // Then
        $this->expectException(LogicException::class);

        // When
        $this->takeOver->activate($this->tenant, $first->kid, $this->context);
    }

    #[Test]
    public function activatingAnUnknownKeyFails(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->takeOver->activate($this->tenant, 'nope', $this->context);
    }

    #[Test]
    public function aRotationActivatesTheNewKey(): void
    {
        // Given
        $this->firstRotation();

        // When
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(Keys::otherPair()->kid, $second->kid);
        static::assertSame($second, $this->repository->findActive($this->tenant, Algorithms::rs256()));
    }

    #[Test]
    public function aRotationStartsRetiringThePreviousKeyAndKeepsItPublished(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertEquals($this->clock->now()->add(new DateInterval(KeyLifecycle::LONGEST_LIFETIME)), $first->retirementDueAt);
        static::assertSame([$first, $second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function aRotationSavesTheStagedKeyThenBothKeys(): void
    {
        // Given
        $this->firstRotation();
        $savesBefore = $this->repository->saves;

        // When
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame($savesBefore + 3, $this->repository->saves);
    }

    #[Test]
    public function aRotationAnnouncesWhichKeyIsRetiring(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        $event = $this->events->of(TenantKeyRotated::class)[1];
        static::assertSame($first, $event->retiring);
        static::assertSame($this->tenant, $event->tenant);
        static::assertSame($this->context, $event->context);
        static::assertSame([], $this->events->of(TenantKeyRetired::class));
    }

    #[Test]
    public function theNewKeySignsAtOnce(): void
    {
        // Given
        $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $provider = new SealedKeyProvider($this->repository, Keys::sealer());

        // When
        $active = $provider->activeKey($this->tenant, Algorithms::rs256());

        // Then
        static::assertSame(Keys::otherPair()->privateJwk, $active->privateJwk);
    }

    /**
     * The compromise path: no window, the previous key is out of the JWK Set at once.
     */
    #[Test]
    public function aRotationForACompromiseRetiresThePreviousKeyAtOnce(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $second = $this->takeOver->rotateAfterCompromise($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertEquals($this->clock->now(), $first->retirementDueAt);
        static::assertEquals($this->clock->now(), $first->retiredAt);
        static::assertSame([$second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function aRotationForACompromiseSaysSo(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $this->takeOver->rotateAfterCompromise($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        [$event] = $this->events->of(TenantKeyRetired::class);
        static::assertSame($first, $event->retired);
        static::assertSame(RetirementReason::Compromised, $event->reason);
        static::assertSame($this->context, $event->context);
        static::assertSame($first, $this->events->of(TenantKeyRotated::class)[1]->retiring);
    }

    #[Test]
    public function aRotationForACompromiseWithoutAnActiveKeyActivatesAKey(): void
    {
        // When
        $key = $this->takeOver->rotateAfterCompromise($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        static::assertTrue($key->isActive());
        static::assertSame([], $this->events->of(TenantKeyRetired::class));
    }

    /**
     * Every state of the lifecycle is the same whatever the algorithm: a tenant that signs EdDSA rotates
     * its Ed25519 keys the way it rotates its RSA ones, and the keys of one algorithm ignore the other.
     */
    #[Test]
    public function aKeyOfAnotherAlgorithmRotatesTheSameWay(): void
    {
        // Given
        $lifecycle = new KeyLifecycle(
            $this->clock,
            [new FixedLifetimeArtifact(new DateInterval(KeyLifecycle::LONGEST_LIFETIME))],
            generator: new JwtLibraryKeyPairGenerator(Algorithms::everyUse()),
        );
        $rs256 = $lifecycle->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $first = $lifecycle->takeOver->rotate($this->tenant, Algorithms::edDsa(), $this->context);

        // When
        $second = $lifecycle->takeOver->rotate($this->tenant, Algorithms::edDsa(), $this->context);

        // Then
        static::assertSame($second, $lifecycle->keys->findActive($this->tenant, Algorithms::edDsa()));
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($this->clock->now()->add(new DateInterval(KeyLifecycle::LONGEST_LIFETIME)), $first->retirementDueAt);
        static::assertSame($rs256, $lifecycle->keys->findActive($this->tenant, Algorithms::rs256()));
        static::assertSame('Ed25519', $second->publicJwk['crv']);
    }

    private function firstRotation(): TenantKey
    {
        $key = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+30 days');

        return $key;
    }
}
