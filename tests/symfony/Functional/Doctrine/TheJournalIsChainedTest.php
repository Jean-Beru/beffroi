<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Configuration\JournalSection;
use App\Doctor\Finding;
use App\Doctor\JournalHoldsTogether;
use App\Key\FileJournalCheckpoints;
use App\Message\ForgetTheActsPastTheirRetention;
use App\Message\SignTheJournal;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\ChainOfActsInterface;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use function array_map;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0060
 */
final class TheJournalIsChainedTest extends DatabaseTestCase
{
    protected function tearDown(): void
    {
        new Filesystem()->remove(self::keyStorage() . '/default/' . FileJournalCheckpoints::DIRECTORY);
        parent::tearDown();
    }

    #[Test]
    public function twoActsTakeTwoPositionsThatFollowEachOther(): void
    {
        // Given
        self::anAct();

        // When
        self::anAct();

        // Then
        static::assertSame([1, 2], array_map(
            static fn ($linked): int => $linked->position,
            self::service('test.beffroi.chain_of_acts', ChainOfActsInterface::class)->linkedAfter(self::tenant(), 0, 10),
        ));
    }

    #[Test]
    public function aJournalWrittenByTheProviderHoldsTogether(): void
    {
        // Given
        self::anAct();
        self::anAct();

        // When
        $finding = self::finding();

        // Then
        static::assertSame(
            [true, 'The 2 act(s) the journal keeps, positions 1 to 2, follow one another; none is signed yet, which the next pass does.'],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    #[Test]
    public function anActChangedInTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        self::anAct();
        $changed = self::anAct();
        self::connection()->update('beffroi_journal', ['act' => 'user.signed_out'], ['id' => $changed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The act at position 2 of the journal is not the one written there.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function aProvenanceMovedFromAnotherActIsNamedByItsPosition(): void
    {
        // Given
        $from = self::anAct();
        $to = self::anAct();
        $sealed = self::connection()->fetchOne('SELECT context FROM beffroi_journal WHERE id = ?', [$from->id], [UuidType::NAME]);
        self::connection()->update('beffroi_journal', ['context' => $sealed], ['id' => $to->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The act at position 2 of the journal is not the one written there.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function anActRemovedFromTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        self::anAct();
        $removed = self::anAct();
        self::anAct();
        self::connection()->delete('beffroi_journal', ['id' => $removed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The act at position 2 of the journal is missing.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function theFirstActRemovedAfterTheSignatureIsNamedByItsPosition(): void
    {
        // Given
        $removed = self::anAct();
        self::aSigningKey();
        self::dispatch(new SignTheJournal());
        self::connection()->delete('beffroi_journal', ['id' => $removed->id], ['id' => UuidType::NAME]);

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The act at position 1 of the journal is missing.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function anActAddedToTheDatabaseOutsideTheChainIsSeen(): void
    {
        // Given
        self::anAct();
        $manager = self::entityManager();
        $manager->persist(self::entry(self::now()));
        $manager->flush();

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, '1 act(s) of the journal are not in its chain.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function theSignatureIsKeptBesideTheKeysOfTheTenant(): void
    {
        // Given
        self::aSigningKey();

        // When
        self::dispatch(new SignTheJournal());

        // Then
        static::assertFileExists(self::keyStorage() . '/default/' . FileJournalCheckpoints::DIRECTORY . '/' . FileJournalCheckpoints::FILE);
    }

    #[Test]
    public function aSignedJournalSaysUpToWhereItIsSigned(): void
    {
        // Given
        self::aSigningKey();
        self::dispatch(new SignTheJournal());

        // When
        $finding = self::finding();

        // Then
        static::assertStringContainsString('holds up to position 2; 0 act(s) written since are signed at the next pass.', $finding->lines[0] ?? '');
    }

    #[Test]
    public function anActWhoseMomentIsMovedBackIsNotForgottenByTheRetention(): void
    {
        // Given
        $moved = self::anAct();
        self::aSigningKey();
        self::dispatch(new SignTheJournal());
        self::movedBack($moved);

        // When
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // Then
        static::assertTrue(self::isKept($moved));
    }

    #[Test]
    public function anActWhoseMomentIsMovedBackIsNamedByItsPosition(): void
    {
        // Given
        $moved = self::anAct();
        self::aSigningKey();
        self::dispatch(new SignTheJournal());
        self::movedBack($moved);
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // When
        $finding = self::finding();

        // Then
        static::assertSame([false, 'The act at position 1 of the journal is not the one written there.'], [$finding->green, $finding->lines[0] ?? null]);
    }

    #[Test]
    public function theRetentionForgetsTheOldestActs(): void
    {
        // Given
        $old = self::anAct(self::past());
        self::aSigningKey();

        // When
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // Then
        static::assertFalse(self::isKept($old));
    }

    #[Test]
    public function aJournalTheRetentionCutHoldsTogether(): void
    {
        // Given
        self::anAct(self::past());
        self::aSigningKey();
        self::dispatch(new ForgetTheActsPastTheirRetention());

        // When
        $finding = self::finding();

        // Then
        static::assertTrue($finding->green);
        static::assertStringStartsWith('The 2 act(s) the journal keeps, positions 2 to 3, follow one another, and the signature of ', $finding->lines[0] ?? '');
    }

    private static function anAct(?DateTimeImmutable $occurredAt = null): JournalEntry
    {
        $entry = self::entry($occurredAt ?? self::service('clock', ClockInterface::class)->now());
        self::service('test.beffroi.journal', JournalInterface::class)->record($entry);
        self::reload();

        return $entry;
    }

    private static function entry(DateTimeImmutable $occurredAt): JournalEntry
    {
        return new JournalEntry(Uuid::v7(), self::tenant(), UserAuthenticated::NAME, $occurredAt, self::context());
    }

    /**
     * Its activation is an act of the journal, written now.
     */
    private static function aSigningKey(): void
    {
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());
        self::reload();
    }

    private static function dispatch(object $message): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch($message);
        self::reload();
    }

    private static function finding(): Finding
    {
        return self::service('test.beffroi.journal_holds_together', JournalHoldsTogether::class)->finding();
    }

    private static function past(): DateTimeImmutable
    {
        return self::service('clock', ClockInterface::class)
            ->now()
            ->modify(sprintf('-%d days', JournalSection::DEFAULT_RETENTION + 1));
    }

    private static function movedBack(JournalEntry $act): void
    {
        self::connection()
            ->update(
                'beffroi_journal',
                ['occurred_at' => self::past()->format('Y-m-d H:i:s')],
                ['id' => $act->id],
                ['id' => UuidType::NAME],
            );
    }

    private static function isKept(JournalEntry $act): bool
    {
        return self::connection()->fetchOne('SELECT 1 FROM beffroi_journal WHERE id = ?', [$act->id], [UuidType::NAME]) !== false;
    }

    private static function connection(): Connection
    {
        return self::service('doctrine.dbal.default_connection', Connection::class);
    }
}
