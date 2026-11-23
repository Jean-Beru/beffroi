<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Application\Key\NamedKey;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Event\TenantKeyRetired;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\RetirementReason;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Exception\RetirementNotDueException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeyLifecycle;
use Beffroi\Core\Tests\Fixture\KeysStillNeeded;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.3
 */
final class KeyRetirementTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $repository;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private KeyStaging $staging;

    private KeyTakeOver $takeOver;

    private KeyRetirement $retirement;

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
        $this->retirement = $lifecycle->retirement;
    }

    #[Test]
    public function retireDueRetiresAKeyPastItsRetirementDate(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 hour');
        $savesBefore = $this->repository->saves;

        // When
        $retired = $this->retirement->retireDue($this->tenant, $this->context);

        // Then
        static::assertSame([$first], $retired);
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertEquals($this->clock->now(), $first->retiredAt);
        static::assertSame($savesBefore + 1, $this->repository->saves);
        static::assertSame([$second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function retireDueLeavesAKeyInsideItsRetirementWindow(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+59 minutes 59 seconds');
        $savesBefore = $this->repository->saves;

        // When
        $retired = $this->retirement->retireDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $retired);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame($savesBefore, $this->repository->saves);
        static::assertSame([$first, $second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function retireDueSaysTimeDidIt(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // When
        $this->retirement->retireDue($this->tenant, $this->context);

        // Then
        [$event] = $this->events->of(TenantKeyRetired::class);
        static::assertSame($first, $event->retired);
        static::assertSame(RetirementReason::Due, $event->reason);
        static::assertSame($this->tenant, $event->tenant);
        static::assertSame($this->context, $event->context);
    }

    #[Test]
    public function aDueKeyIsRetiredByHandAsDue(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // When
        $this->retirement->retire($this->tenant, $first->kid, $this->context);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertSame(RetirementReason::Due, $this->events->of(TenantKeyRetired::class)[0]->reason);
        static::assertSame([$second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function aKeyInsideItsRetirementWindowIsNotRetiredBeforeItsDate(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 minute');

        // Then
        $this->expectException(RetirementNotDueException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The key "%s" is not due for retirement before 2026-10-15T15:00:00+00:00: what it is bound to may still be alive.',
            $first->kid,
        ));

        // When
        $this->retirement->retire($this->tenant, $first->kid, $this->context);
    }

    #[Test]
    public function aKeyInsideItsRetirementWindowStaysPublishedAfterTheRefusal(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);

        // When
        try {
            $this->retirement->retire($this->tenant, $first->kid, $this->context);
        } catch (RetirementNotDueException) {
        }

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame([$first, $second], $this->repository->findInService($this->tenant));
        static::assertSame([], $this->events->of(TenantKeyRetired::class));
    }

    #[Test]
    public function retiringAKeyBeforeItsDateRetiresItAsForced(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 minute');

        // When
        $this->retirement->retireBeforeItsDate($this->tenant, $first->kid, $this->context);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertEquals($this->clock->now(), $first->retiredAt);
        static::assertSame(RetirementReason::Forced, $this->events->of(TenantKeyRetired::class)[0]->reason);
        static::assertSame([$second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function retiringADueKeyBeforeItsDateStillSaysTimeDidIt(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // When
        $this->retirement->retireBeforeItsDate($this->tenant, $first->kid, $this->context);

        // Then
        static::assertSame(RetirementReason::Due, $this->events->of(TenantKeyRetired::class)[0]->reason);
    }

    #[Test]
    public function retireDueLeavesADueKeyThatIsStillNeeded(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // When
        $retired = $this->retirementHeldFor([$first->kid])->retireDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $retired);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame([$first, $second], $this->repository->findInService($this->tenant));
    }

    #[Test]
    public function retireDueRetiresADueKeyNothingNeedsAnyMore(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // When
        $retired = $this->retirementHeldFor(['another-key'])->retireDue($this->tenant, $this->context);

        // Then
        static::assertSame([$first], $retired);
    }

    #[Test]
    public function aDueKeyThatIsStillNeededIsNotRetiredByHand(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // Then
        $this->expectException(RetirementNotDueException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The key "%s" still opens %s: its retirement waits until nothing needs it any more.',
            $first->kid,
            KeysStillNeeded::NAME,
        ));

        // When
        $this->retirementHeldFor([$first->kid])->retire($this->tenant, $first->kid, $this->context);
    }

    #[Test]
    public function retiringADueKeyThatIsStillNeededBeforeItsDateRetiresItAsForced(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 day');

        // When
        $this->retirementHeldFor([$first->kid])->retireBeforeItsDate($this->tenant, $first->kid, $this->context);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertSame(RetirementReason::Forced, $this->events->of(TenantKeyRetired::class)[0]->reason);
    }

    #[Test]
    public function theActiveKeyCannotBeRetiredWithoutARotation(): void
    {
        // Given
        $key = $this->firstRotation();

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The active key cannot be retired; rotate first.');

        // When
        $this->retirement->retireBeforeItsDate($this->tenant, $key->kid, $this->context);
    }

    #[Test]
    public function aStagedKeyCannotBeRetired(): void
    {
        // Given
        $staged = $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Only a retiring key can be retired; this one is staged.');

        // When
        $this->retirement->retireBeforeItsDate($this->tenant, $staged->kid, $this->context);
    }

    #[Test]
    public function retiringAnUnknownKeyFails(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->retirement->retire($this->tenant, 'nope', $this->context);
    }

    /**
     * @param list<string> $kids
     */
    private function retirementHeldFor(array $kids): KeyRetirement
    {
        return new KeyRetirement($this->repository, new NamedKey($this->repository), $this->clock, $this->events, [new KeysStillNeeded($kids)]);
    }

    private function firstRotation(): TenantKey
    {
        $key = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+30 days');

        return $key;
    }
}
