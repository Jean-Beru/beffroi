<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Confirmation;

use App\Confirmation\RateLimitedConfirmationSends;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateInterval;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;
use Symfony\Component\RateLimiter\Storage\CacheStorage;

/**
 * Decision 0014
 */
final class RateLimitedConfirmationSendsTest extends TestCase
{
    private const string NUMBER = '+33612345678';

    private ArrayAdapter $store;

    protected function setUp(): void
    {
        $this->store = new ArrayAdapter();
    }

    #[Test]
    public function aPersonIsSentNoMoreThanTheirBudget(): void
    {
        // Given
        $sends = $this->sends(personLimit: 2, addressLimit: 3);
        $alice = Fixtures::user();
        $sends->spend($alice, '+33611111111');
        $sends->spend($alice, '+33622222222');

        // When
        $spent = $sends->spend($alice, '+33633333333');

        // Then
        static::assertFalse($spent);
    }

    #[Test]
    public function anAddressReceivesNoMoreThanItsBudget(): void
    {
        // Given
        $sends = $this->sends(personLimit: 2, addressLimit: 3);
        $alice = Fixtures::user();
        $bob = Fixtures::user(username: 'bob', subject: 'bob-subject');
        $sends->spend($alice, self::NUMBER);
        $sends->spend($alice, self::NUMBER);
        $sends->spend($bob, self::NUMBER);

        // When
        $spent = $sends->spend($bob, self::NUMBER);

        // Then
        static::assertFalse($spent);
    }

    #[Test]
    public function aSendWithinBothBudgetsIsSpent(): void
    {
        // Given
        $sends = $this->sends(personLimit: 2, addressLimit: 3);
        $sends->spend(Fixtures::user(), self::NUMBER);

        // When
        $spent = $sends->spend(Fixtures::user(username: 'bob', subject: 'bob-subject'), self::NUMBER);

        // Then
        static::assertTrue($spent);
    }

    #[Test]
    public function anAddressIsCountedWhateverTheWayItIsWritten(): void
    {
        // Given
        $sends = $this->sends(personLimit: 1, addressLimit: 2);
        $sends->spend(Fixtures::user(), '+33 6 12 34 56 78');
        $sends->spend(Fixtures::user(username: 'bob', subject: 'bob-subject'), '+33.6-12-34-56-(78)');

        // When
        $spent = $sends->spend(Fixtures::user(username: 'carol', subject: 'carol-subject'), self::NUMBER);

        // Then
        static::assertFalse($spent);
    }

    #[Test]
    public function theStoreHoldsNoAddressInClear(): void
    {
        // Given
        $sends = $this->sends(personLimit: 2, addressLimit: 3);

        // When
        $sends->spend(Fixtures::user(), self::NUMBER);

        // Then
        static::assertStringNotContainsString(self::NUMBER, serialize($this->store->getValues()));
    }

    #[Test]
    public function aBudgetOfAnAddressNoLargerThanTheOneOfAPersonIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('"confirmation.sends.address_limit"');

        // When
        $this->sends(personLimit: 3, addressLimit: 3);
    }

    private function sends(int $personLimit, int $addressLimit): RateLimitedConfirmationSends
    {
        return new RateLimitedConfirmationSends(
            $personLimit,
            $addressLimit,
            new DateInterval('P1D'),
            new CacheStorage($this->store),
            new LockFactory(new InMemoryStore()),
            'the secret of the kernel',
        );
    }
}
