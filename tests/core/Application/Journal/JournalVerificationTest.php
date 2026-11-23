<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Journal;

use Beffroi\Core\Exception\BrokenJournalException;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenActs;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedJournal;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0058
 */
final class JournalVerificationTest extends TestCase
{
    private SignedJournal $journal;

    protected function setUp(): void
    {
        $this->journal = new SignedJournal();
    }

    #[Test]
    public function aJournalWithNoActHoldsTogether(): void
    {
        // When
        $verified = $this->journal->verification()->verify($this->journal->tenant);

        // Then
        static::assertSame([0, null], [$verified->end->position, $verified->signed]);
    }

    #[Test]
    public function actsWrittenOneAfterAnotherFollowEachOther(): void
    {
        // Given
        $this->writeThree();

        // When
        $verified = $this->journal->verification()->verify($this->journal->tenant);

        // Then
        static::assertTrue($verified->end->equals($this->journal->chain->head));
    }

    #[Test]
    public function anActChangedInTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        $this->writeThree();
        $this->journal->chain->rewrite(2, ChainOfWrittenActs::act('user.signed_out', Fixtures::now()));

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The act at position 2 of the journal is not the one written there.');

        // When
        $this->journal->verification()->verify($this->journal->tenant);
    }

    #[Test]
    public function anActRemovedFromTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        $this->writeThree();
        $this->journal->chain->remove(2);

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The act at position 2 of the journal is missing.');

        // When
        $this->journal->verification()->verify($this->journal->tenant);
    }

    #[Test]
    public function anActAddedToTheDatabaseOutsideTheChainIsSeen(): void
    {
        // Given
        $this->writeThree();
        $this->journal->chain->insertWithoutALink();

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('1 act(s) of the journal are not in its chain.');

        // When
        $this->journal->verification()->verify($this->journal->tenant);
    }

    #[Test]
    public function aSignedActRewrittenWithEveryLinkComputedAgainIsSeenAtTheSignedPosition(): void
    {
        // Given
        $this->writeThree();
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->rewriteAndRelink(2, ChainOfWrittenActs::act('user.signed_out', Fixtures::now()));

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The acts up to position 3 of the journal are not the ones signed.');

        // When
        $this->journal->verification()->verify($this->journal->tenant);
    }

    #[Test]
    public function theLastSignedActRemovedIsSeen(): void
    {
        // Given
        $this->writeThree();
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->remove(3);

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The acts from position 3 to position 3 of the journal are missing.');

        // When
        $this->journal->verification()->verify($this->journal->tenant);
    }

    #[Test]
    public function aSignatureThatDoesNotVerifyIsSeen(): void
    {
        // Given
        $this->writeThree();
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->kept->putBack('eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl');

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The last signature of the journal does not verify: The token does not name its key.');

        // When
        $this->journal->verification()->verify($this->journal->tenant);
    }

    #[Test]
    public function theActsWrittenSinceTheLastSignatureAreCounted(): void
    {
        // Given
        $this->writeThree();
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->write();

        // When
        $verified = $this->journal->verification()->verify($this->journal->tenant);

        // Then
        static::assertSame(1, $verified->unsigned());
    }

    private function writeThree(): void
    {
        $this->journal->chain->write();
        $this->journal->chain->write();
        $this->journal->chain->write();
    }
}
