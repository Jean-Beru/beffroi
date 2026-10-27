<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Load;

use DateInterval;
use Beffroi\Bundle\Load\LoadBudget;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * Decision 0014: a budget that bounds a load counts what is asked of it on a key, refuses what finds the
 * window full, and hands the refusal the delay to wait and the name it answers to.
 */
final class LoadBudgetTest extends TestCase
{
    private const int LIMIT = 3;

    #[Test]
    public function itTakesWhatTheWindowHasRoomFor(): void
    {
        // Given
        $budget = self::budget();

        // When
        for ($request = 1; $request <= self::LIMIT; ++$request) {
            $budget->consume('198.51.100.7');
        }

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function itRefusesTheRequestPastTheWindow(): void
    {
        // Given
        $budget = self::budget();
        for ($request = 1; $request <= self::LIMIT; ++$request) {
            $budget->consume('198.51.100.7');
        }

        // Then
        $this->expectException(LoadBudgetSpentException::class);

        // When
        $budget->consume('198.51.100.7');
    }

    /**
     * RFC 9110 §10.2.3: the delay a refusal carries, which is never zero, and the budget that refused.
     */
    #[Test]
    public function aRefusalNamesItsBudgetAndTheDelayToWait(): void
    {
        // Given
        $budget = self::budget(1);
        $budget->consume('198.51.100.7');

        // When
        try {
            $budget->consume('198.51.100.7');
            static::fail('The budget is spent.');
        } catch (LoadBudgetSpentException $spent) {
            // Then
            static::assertSame(LoadBudget::ORIGIN, $spent->budget);
            static::assertGreaterThan(0, $spent->retryAfter);
            static::assertNull($spent->client);
        }
    }

    /**
     * Decision 0014: a budget is counted on a key, so what one caller spent is nothing to another.
     */
    #[Test]
    public function whatOneKeySpendsIsNotCountedOnAnother(): void
    {
        // Given
        $budget = self::budget(1);
        $budget->consume('198.51.100.7');

        // When
        $budget->consume('198.51.100.8');

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * The audit trail is told which client a refusal was counted on, when the caller knows one.
     */
    #[Test]
    public function aRefusalCarriesTheClientItWasCountedOn(): void
    {
        // Given
        $budget = self::budget(1);
        $budget->consume('a-tenant|a-client', 'a-client');

        // When
        try {
            $budget->consume('a-tenant|a-client', 'a-client');
            static::fail('The budget is spent.');
        } catch (LoadBudgetSpentException $spent) {
            // Then
            static::assertSame('a-client', $spent->client);
        }
    }

    /**
     * Issue #913: the tree holds a written limit to one request at least, and a number an environment
     * variable carries is held to it when the budget is built.
     */
    #[Test]
    public function itIsNotBuiltForNoRequest(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "load.origin.limit" is a number of requests of at least 1, 0 given.');

        // When
        self::budget(0);
    }

    private static function budget(int $limit = self::LIMIT): LoadBudget
    {
        return new LoadBudget(LoadBudget::ORIGIN, $limit, new DateInterval('PT60S'), new InMemoryStorage());
    }
}
