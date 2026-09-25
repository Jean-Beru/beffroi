<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Load;

use DateInterval;
use Heidi\Bundle\Load\LoadBudget;
use Heidi\Bundle\Load\RateLimitedClientLoad;
use Heidi\Core\Exception\LoadBudgetSpentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * Decision 0014: the budget of a client is counted by tenant and by client, because two tenants may
 * register the same identifier and one bucket for both would make either pay for the other.
 */
final class RateLimitedClientLoadTest extends TestCase
{
    private const int BUDGET = 1;

    #[Test]
    public function aClientPastItsWindowIsRefused(): void
    {
        // Given
        $budget = self::budget();
        $tenant = Fixtures::tenant();
        $budget->consume($tenant, 'a-client');

        // When
        try {
            $budget->consume($tenant, 'a-client');
            static::fail('The budget of the client is spent.');
        } catch (LoadBudgetSpentException $spent) {
            // Then
            static::assertSame(LoadBudget::CLIENT, $spent->budget);
            static::assertSame('a-client', $spent->client);
        }
    }

    #[Test]
    public function anotherClientOfTheSameTenantHasAWindowOfItsOwn(): void
    {
        // Given
        $budget = self::budget();
        $tenant = Fixtures::tenant();
        $budget->consume($tenant, 'a-client');

        // When
        $budget->consume($tenant, 'another-client');

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function theSameClientOfAnotherTenantHasAWindowOfItsOwn(): void
    {
        // Given
        $budget = self::budget();
        $budget->consume(Fixtures::tenant(), 'a-client');

        // When
        $budget->consume(Fixtures::tenant('other', 'https://id.other.example'), 'a-client');

        // Then
        $this->expectNotToPerformAssertions();
    }

    private static function budget(): RateLimitedClientLoad
    {
        return new RateLimitedClientLoad(new LoadBudget(LoadBudget::CLIENT, self::BUDGET, new DateInterval('PT60S'), new InMemoryStorage()));
    }
}
