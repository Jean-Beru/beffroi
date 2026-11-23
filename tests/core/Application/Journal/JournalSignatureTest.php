<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Journal;

use Beffroi\Core\Application\Journal\JournalCheckpoints;
use Beffroi\Core\Domain\Journal\Link;
use Beffroi\Core\Exception\BrokenJournalException;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenActs;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedJournal;
use function base64_decode;
use function explode;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtr;

/**
 * Decision 0060, RFC 8725 §3.11
 */
final class JournalSignatureTest extends TestCase
{
    private SignedJournal $journal;

    protected function setUp(): void
    {
        $this->journal = new SignedJournal();
        $this->journal->chain->write();
        $this->journal->chain->write();
    }

    #[Test]
    public function theSignatureNamesTheHeadOfTheChain(): void
    {
        // When
        $checkpoint = $this->journal->signature()->sign($this->journal->tenant);

        // Then
        static::assertTrue($checkpoint->head->equals($this->journal->chain->head));
    }

    #[Test]
    public function theSignatureIsTakenUnderTheLockOfTheHead(): void
    {
        // When
        $this->journal->signature()->sign($this->journal->tenant);

        // Then
        static::assertSame(1, $this->journal->chain->locks);
    }

    #[Test]
    public function theSignatureIsAJwsOfTheTypeOfACheckpointOfTheJournal(): void
    {
        // When
        $this->journal->signature()->sign($this->journal->tenant);

        // Then
        $header = json_decode(
            (string) base64_decode(strtr(explode('.', (string) $this->journal->kept->last($this->journal->tenant))[0], '-_', '+/'), true),
            true,
            8,
            JSON_THROW_ON_ERROR,
        );
        static::assertIsArray($header);
        static::assertSame(JournalCheckpoints::TYPE, $header['typ'] ?? null);
    }

    #[Test]
    public function aFirstSignatureKeepsTheChainFromItsFirstAct(): void
    {
        // When
        $checkpoint = $this->journal->signature()->sign($this->journal->tenant);

        // Then
        static::assertTrue($checkpoint->keptAfter->equals(Link::beforeTheFirst()));
    }

    #[Test]
    public function aLaterSignatureKeepsWhatTheLastOneKept(): void
    {
        // Given
        $this->journal->chain->forgetUpTo($this->journal->tenant, 1);
        $first = $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->write();

        // When
        $checkpoint = $this->journal->signature()->sign($this->journal->tenant);

        // Then
        static::assertTrue($checkpoint->keptAfter->equals($first->keptAfter));
    }

    #[Test]
    public function aChainRewrittenBeforeTheLastSignatureIsNotSignedAgain(): void
    {
        // Given
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->rewriteAndRelink(1, ChainOfWrittenActs::act('user.signed_out', Fixtures::now()));
        $this->journal->chain->write();

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The act at position 3 of the journal is not the one written there.');

        // When
        $this->journal->signature()->sign($this->journal->tenant);
    }

    #[Test]
    public function aChainThatIsNotSignedAgainKeepsTheLastSignature(): void
    {
        // Given
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->chain->rewriteAndRelink(1, ChainOfWrittenActs::act('user.signed_out', Fixtures::now()));
        $this->journal->chain->write();

        // When
        try {
            $this->journal->signature()->sign($this->journal->tenant);
        } catch (BrokenJournalException) {
        }

        // Then
        static::assertCount(1, $this->journal->kept->kept);
    }

    #[Test]
    public function aSignatureUnderAKeyTheTenantNoLongerPublishesStopsTheNextOne(): void
    {
        // Given
        $this->journal->signature()->sign($this->journal->tenant);
        $this->journal->retireTheKeyThatSigned();

        // Then
        $this->expectException(BrokenJournalException::class);
        $this->expectExceptionMessageIs('The last signature of the journal does not verify: The token names a key this tenant does not publish.');

        // When
        $this->journal->signature()->sign($this->journal->tenant);
    }
}
