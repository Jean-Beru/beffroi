<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Lock;

use App\Lock\LockedSections;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;

/**
 * Decision 0026
 */
final class LockedSectionsTest extends TestCase
{
    private const string NAME = 'beffroi.ticket.the-ticket';

    private LockFactory $locks;

    private LockedSections $sections;

    protected function setUp(): void
    {
        $this->locks = new LockFactory(new InMemoryStore());
        $this->sections = new LockedSections($this->locks);
    }

    #[Test]
    public function aSectionRunsUnderTheLockOfItsName(): void
    {
        // When
        $anotherTookIt = $this->sections->exclusively(self::NAME, fn (): bool => $this->locks->createLock(self::NAME)->acquire());

        // Then
        static::assertFalse($anotherTookIt);
    }

    #[Test]
    public function aSectionAnswersWhatItsWorkAnswers(): void
    {
        // When / Then
        static::assertSame('written', $this->sections->exclusively(self::NAME, static fn (): string => 'written'));
    }

    #[Test]
    public function theLockIsReleasedOnceTheSectionIsOver(): void
    {
        // Given
        $this->sections->exclusively(self::NAME, static fn (): string => 'written');

        // When / Then
        static::assertTrue($this->locks->createLock(self::NAME)->acquire());
    }

    #[Test]
    public function theLockIsReleasedWhenTheSectionFails(): void
    {
        // Given
        try {
            $this->sections->exclusively(self::NAME, static fn (): never => throw new LogicException('The write failed.'));
        } catch (LogicException) {
        }

        // When / Then
        static::assertTrue($this->locks->createLock(self::NAME)->acquire());
    }
}
