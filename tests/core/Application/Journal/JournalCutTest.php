<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Journal;

use Beffroi\Core\Application\Journal\JournalCut;
use Beffroi\Core\Exception\BrokenJournalException;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenActs;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedJournal;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Decision 0058
 */
final class JournalCutTest extends TestCase
{
    private SignedJournal $journal;

    protected function setUp(): void
    {
        $this->journal = new SignedJournal();
    }

    #[Test]
    public function theOldestActsPastTheWindowAreForgotten(): void
    {
        // Given
        $this->journal->chain->write(occurredAt: self::past());
        $this->journal->chain->write(occurredAt: self::past());
        $this->journal->chain->write();

        // When
        $forgotten = $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);

        // Then
        static::assertSame(2, $forgotten);
    }

    #[Test]
    public function theCutIsSigned(): void
    {
        // Given
        $this->journal->chain->write(occurredAt: self::past());
        $cut = $this->journal->chain->write(occurredAt: self::past());
        $this->journal->chain->write();

        // When
        $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);

        // Then
        static::assertTrue($this->journal->checkpoints->last($this->journal->tenant)?->keptAfter->equals($cut));
    }

    #[Test]
    public function aJournalTheRetentionCutHoldsTogether(): void
    {
        // Given
        $this->journal->chain->write(occurredAt: self::past());
        $this->journal->chain->write();
        $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);

        // When
        $verified = $this->journal->verification()->verify($this->journal->tenant);

        // Then
        static::assertSame([1, 2], [$verified->start->position, $verified->end->position]);
    }

    #[Test]
    public function anActPastTheWindowWrittenAfterOneInsideItWaitsForItsTurn(): void
    {
        // Given
        $this->journal->chain->write();
        $this->journal->chain->write(occurredAt: self::past());

        // When
        $forgotten = $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);

        // Then
        static::assertSame(0, $forgotten);
    }

    #[Test]
    public function aRetentionThatForgetsNothingSignsNothing(): void
    {
        // Given
        $this->journal->chain->write();

        // When
        $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);

        // Then
        static::assertSame([], $this->journal->kept->kept);
    }

    #[Test]
    public function anActWhoseMomentWasMovedBackPastTheWindowIsNotForgotten(): void
    {
        // Given
        $this->journal->chain->write();
        $this->journal->chain->write();
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->rewrite(1, ChainOfWrittenActs::act('user.authenticated', self::past()));

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The act at position 1 of the journal is not the one written there.');

        // When
        $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);
    }

    #[Test]
    public function aJournalThatDoesNotFollowKeepsEveryAct(): void
    {
        // Given
        $this->journal->chain->write(occurredAt: self::past());
        $this->journal->chain->write();
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->write();
        $this->journal->chain->rewrite(3, ChainOfWrittenActs::act('user.signed_out', Fixtures::now()));

        // When
        try {
            $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);
        } catch (BrokenJournalException) {
        }

        // Then
        static::assertSame(3, $this->journal->chain->linkedAfter($this->journal->tenant, 0, 10)[2]->position);
    }

    #[Test]
    public function aBacklogIsForgottenOverSeveralPasses(): void
    {
        // Given
        for ($written = 0; $written <= JournalCut::FORGOTTEN_AT_ONCE; ++$written) {
            $this->journal->chain->write(occurredAt: self::past());
        }

        // When
        $forgotten = $this->journal->cut()->forgetPastTheWindow($this->journal->tenant);

        // Then
        static::assertSame(JournalCut::FORGOTTEN_AT_ONCE, $forgotten);
    }

    private static function past(): DateTimeImmutable
    {
        return Fixtures::now()->modify(sprintf('-%d days', SignedJournal::RETENTION + 1));
    }
}
