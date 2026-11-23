<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use Beffroi\Core\Bridge\InMemory\InMemoryTotpUses;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6238 §5.2
 */
final class InMemoryTotpUsesTest extends TestCase
{
    private TotpCredential $totp;

    protected function setUp(): void
    {
        $this->totp = Totps::credential(Fixtures::user(), new FakePasswordHasher(), lastAcceptedStep: 100);
    }

    #[Test]
    public function aLaterStepIsAccepted(): void
    {
        // When / Then
        static::assertTrue(new InMemoryTotpUses()->acceptStep($this->totp, 101, Fixtures::now()));
    }

    #[Test]
    public function aLaterStepIsRecordedOnTheCredential(): void
    {
        // When
        new InMemoryTotpUses()->acceptStep($this->totp, 101, Fixtures::now());

        // Then
        static::assertSame(101, $this->totp->lastAcceptedStep);
        static::assertEquals(Fixtures::now(), $this->totp->lastUsedAt);
    }

    #[Test]
    #[DataProvider('provideStepsAlreadyPassed')]
    public function aStepTheCredentialHasPassedIsRefused(int $step): void
    {
        // When / Then
        static::assertFalse(new InMemoryTotpUses()->acceptStep($this->totp, $step, Fixtures::now()));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStepsAlreadyPassed(): iterable
    {
        yield 'the same step' => [100];
        yield 'an earlier step' => [99];
    }

    #[Test]
    public function aStepRefusedLeavesTheCredentialAsItWas(): void
    {
        // When
        new InMemoryTotpUses()->acceptStep($this->totp, 100, Fixtures::now());

        // Then
        static::assertSame(100, $this->totp->lastAcceptedStep);
        static::assertNull($this->totp->lastUsedAt);
    }

    #[Test]
    public function anUnspentBackupCodeIsSpent(): void
    {
        // When / Then
        static::assertTrue(new InMemoryTotpUses()->spendBackupCode($this->totp, 3, Fixtures::now()));
    }

    #[Test]
    public function aBackupCodeSpentIsRecordedOnTheCredential(): void
    {
        // When
        new InMemoryTotpUses()->spendBackupCode($this->totp, 3, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $this->totp->backupCodes[3]->usedAt);
        static::assertEquals(Fixtures::now(), $this->totp->lastUsedAt);
    }

    #[Test]
    public function aBackupCodeSpentAlreadyIsRefused(): void
    {
        // Given
        $this->totp->spendBackupCode(3, Fixtures::now()->modify('-1 minute'));

        // When / Then
        static::assertFalse(new InMemoryTotpUses()->spendBackupCode($this->totp, 3, Fixtures::now()));
    }

    #[Test]
    public function aPositionPastTheListIsRefused(): void
    {
        // When / Then
        static::assertFalse(new InMemoryTotpUses()->spendBackupCode($this->totp, 10, Fixtures::now()));
    }
}
