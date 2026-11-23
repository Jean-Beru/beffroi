<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use Beffroi\Core\Bridge\InMemory\InMemoryPasskeyUses;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * WebAuthn Level 3 §6.1.1, Decision 0034
 */
final class InMemoryPasskeyUsesTest extends TestCase
{
    private PasskeyCredential $passkey;

    protected function setUp(): void
    {
        $this->passkey = Fixtures::passkey(Fixtures::user());
        $this->passkey->recordUse(Fixtures::authenticatorData(signCount: 5), Fixtures::now()->modify('-1 day'));
    }

    #[Test]
    public function aCounterThatGrewIsAccepted(): void
    {
        // When / Then
        static::assertTrue(new InMemoryPasskeyUses()->recordUse($this->passkey, Fixtures::authenticatorData(signCount: 6), Fixtures::now()));
    }

    #[Test]
    public function aCounterThatGrewIsRecordedOnThePasskey(): void
    {
        // When
        new InMemoryPasskeyUses()->recordUse($this->passkey, Fixtures::authenticatorData(signCount: 6), Fixtures::now());

        // Then
        static::assertSame(6, $this->passkey->signCount);
        static::assertEquals(Fixtures::now(), $this->passkey->lastUsedAt);
    }

    #[Test]
    #[DataProvider('provideCountersThatDidNotGrow')]
    public function aCounterThatDidNotGrowIsRefused(int $counter): void
    {
        // When / Then
        static::assertFalse(new InMemoryPasskeyUses()->recordUse($this->passkey, Fixtures::authenticatorData(signCount: $counter), Fixtures::now()));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideCountersThatDidNotGrow(): iterable
    {
        yield 'the same counter' => [5];
        yield 'a lower counter' => [4];
        yield 'zero after a counter' => [0];
    }

    #[Test]
    public function aCounterRefusedLeavesThePasskeyAsItWas(): void
    {
        // When
        new InMemoryPasskeyUses()->recordUse($this->passkey, Fixtures::authenticatorData(signCount: 5), Fixtures::now());

        // Then
        static::assertSame(5, $this->passkey->signCount);
        static::assertEquals(Fixtures::now()->modify('-1 day'), $this->passkey->lastUsedAt);
    }

    #[Test]
    public function twoCountersAtZeroAreAccepted(): void
    {
        // Given
        $passkey = Fixtures::passkey(Fixtures::user());

        // When / Then
        static::assertTrue(new InMemoryPasskeyUses()->recordUse($passkey, Fixtures::authenticatorData(signCount: 0), Fixtures::now()));
    }
}
