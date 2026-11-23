<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Beffroi\Oidc\Port\PersonsBudgetInterface;
use const PHP_INT_MAX;

/**
 * A budget of so many persons for each administrator, which counts what each one was delivered.
 */
final class FakePersonsBudget implements PersonsBudgetInterface
{
    public const int RETRY_AFTER = 42;

    /**
     * @var array<string, int> the persons spent, by the subject of the administrator
     */
    public private(set) array $spent = [];

    public function __construct(
        private readonly int $persons = PHP_INT_MAX,
    ) {
    }

    public function spend(ActingAdministrator $administrator, int $persons): void
    {
        $spent = $this->spent[$administrator->user->subject->value] ?? 0;
        if (($spent + $persons) > $this->persons) {
            throw new PersonsBudgetSpentException(self::RETRY_AFTER);
        }
        $this->spent[$administrator->user->subject->value] = $spent + $persons;
    }
}
