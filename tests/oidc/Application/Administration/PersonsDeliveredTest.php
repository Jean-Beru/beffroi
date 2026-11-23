<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Administration;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Administration\PersonsDelivered;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\ReadRefusedToAnAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Beffroi\Oidc\Tests\Fixture\FakePersonsBudget;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0014, the budget of the persons an administrator reads; decision 0022.
 */
final class PersonsDeliveredTest extends TestCase
{
    #[Test]
    public function theReadSpendsThePersonsItDelivers(): void
    {
        // Given
        $budget = new FakePersonsBudget(10);
        $delivered = new PersonsDelivered($budget, new RecordingEventDispatcher());

        // When
        $delivered->spend(self::administrator(), 3, Fixtures::context());

        // Then
        static::assertSame(['administrator-subject' => 3], $budget->spent);
    }

    #[Test]
    public function aReadThatDeliversNobodySpendsNothing(): void
    {
        // Given
        $budget = new FakePersonsBudget(10);
        $delivered = new PersonsDelivered($budget, new RecordingEventDispatcher());

        // When
        $delivered->spend(self::administrator(), 0, Fixtures::context());

        // Then
        static::assertSame([], $budget->spent);
    }

    #[Test]
    public function aReadPastTheBudgetIsRefusedWithTheDelayBeforeTheNextOne(): void
    {
        // Given
        $delivered = new PersonsDelivered(new FakePersonsBudget(2), new RecordingEventDispatcher());

        // When
        try {
            $delivered->spend(self::administrator(), 3, Fixtures::context());
            static::fail('A read past the budget is refused.');
        } catch (PersonsBudgetSpentException $exception) {
            // Then
            static::assertSame(FakePersonsBudget::RETRY_AFTER, $exception->retryAfter);
        }
    }

    #[Test]
    public function theRefusalIsAnActOfTheAdministratorInTheirOwnJournal(): void
    {
        // Given
        $events = new RecordingEventDispatcher();
        $delivered = new PersonsDelivered(new FakePersonsBudget(2), $events);
        $administrator = self::administrator();

        // When
        try {
            $delivered->spend($administrator, 3, Fixtures::context());
        } catch (PersonsBudgetSpentException) {
        }

        // Then
        $refusals = $events->of(ReadRefusedToAnAdministrator::class);
        static::assertSame(
            [['administration.read_refused', 'administrator-subject', 'beffroi-tui', $administrator->tenant]],
            array_map(static fn (ReadRefusedToAnAdministrator $refusal): array => [
                $refusal->name(),
                $refusal->subject()->value,
                $refusal->clientId,
                $refusal->tenant,
            ], $refusals),
        );
    }

    #[Test]
    public function aReadWithinTheBudgetWritesNoRefusal(): void
    {
        // Given
        $events = new RecordingEventDispatcher();
        $delivered = new PersonsDelivered(new FakePersonsBudget(3), $events);

        // When
        $delivered->spend(self::administrator(), 3, Fixtures::context());

        // Then
        static::assertSame([], $events->events);
    }

    private static function administrator(): ActingAdministrator
    {
        $tenant = Fixtures::tenant();

        return new ActingAdministrator($tenant, Fixtures::user($tenant, 'administrator', 'administrator-subject'), 'beffroi-tui', Uuid::v7());
    }
}
