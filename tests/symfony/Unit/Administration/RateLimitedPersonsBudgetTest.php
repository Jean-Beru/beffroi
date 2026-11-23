<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Administration;

use App\Administration\RateLimitedPersonsBudget;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use DateInterval;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0059, the budget of the persons an administrator reads.
 */
final class RateLimitedPersonsBudgetTest extends TestCase
{
    private const int LIMIT = 100;

    #[Test]
    public function personsWithinTheBudgetAreSpent(): void
    {
        // Given
        $budget = self::budget();
        $administrator = self::administrator(Fixtures::tenant(), 'alice');

        // When
        $budget->spend($administrator, self::LIMIT);

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function anAdministratorPastTheirBudgetIsRefusedWithADelay(): void
    {
        // Given
        $budget = self::budget();
        $administrator = self::administrator(Fixtures::tenant(), 'alice');
        $budget->spend($administrator, self::LIMIT - 1);

        // When
        try {
            $budget->spend($administrator, 2);
            static::fail('The budget of the administrator is spent.');
        } catch (PersonsBudgetSpentException $spent) {
            // Then
            static::assertGreaterThan(0, $spent->retryAfter);
        }
    }

    #[Test]
    public function aRefusedReadSpendsNothing(): void
    {
        // Given
        $budget = self::budget();
        $administrator = self::administrator(Fixtures::tenant(), 'alice');
        $budget->spend($administrator, self::LIMIT - 1);
        try {
            $budget->spend($administrator, 2);
        } catch (PersonsBudgetSpentException) {
        }

        // When
        $budget->spend($administrator, 1);

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function anotherAdministratorOfTheSameTenantKeepsTheirOwnBudget(): void
    {
        // Given
        $budget = self::budget();
        $tenant = Fixtures::tenant();
        $budget->spend(self::administrator($tenant, 'alice'), self::LIMIT);

        // When
        $budget->spend(self::administrator($tenant, 'bob'), self::LIMIT);

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aLimitBelowTheLargestPageOfMembersIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "administrator.persons.limit" is a number of persons of at least 100, 99 given.');

        // When
        new RateLimitedPersonsBudget(99, new DateInterval('PT3600S'), new InMemoryStorage(), new LockFactory(new InMemoryStore()));
    }

    private static function budget(): RateLimitedPersonsBudget
    {
        return new RateLimitedPersonsBudget(self::LIMIT, new DateInterval('PT3600S'), new InMemoryStorage(), new LockFactory(new InMemoryStore()));
    }

    private static function administrator(Tenant $tenant, string $username): ActingAdministrator
    {
        return new ActingAdministrator($tenant, Fixtures::user($tenant, $username, $username . '-subject'), 'administration-app', Uuid::v7());
    }
}
