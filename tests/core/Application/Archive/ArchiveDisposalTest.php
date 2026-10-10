<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive;

use Beffroi\Core\Application\Archive\ArchiveDisposal;
use Beffroi\Core\Bridge\InMemory\InMemoryPersonalArchiveRepository;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Event\PersonDroppedTheirArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the person who has their file has this provider drop it, before the date it would have gone
 * away on by itself. The row goes and leaves nothing behind.
 */
final class ArchiveDisposalTest extends TestCase
{
    private const string DOCUMENT = '{"profile":[]}';

    #[Test]
    public function theFileOfThePersonWhoAsksIsDropped(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        self::built($archives, $user);

        // When
        self::dropping($archives)->droppedBy($user, Fixtures::context());

        // Then
        static::assertSame(0, $archives->count());
    }

    /**
     * The act is written to the journal, where it says what became of the request: the identifier is all
     * that is left of the archive once the row is gone.
     */
    #[Test]
    public function droppingTheFileAnnouncesTheAct(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::built($archives, $user);
        $events = new RecordingEventDispatcher();

        // When
        self::dropping($archives, $events)->droppedBy($user, Fixtures::context());

        // Then
        $announced = $events->of(PersonDroppedTheirArchive::class);
        static::assertCount(1, $announced);
        static::assertTrue($announced[0]->archiveId->equals($archive->id));
    }

    /**
     * Nothing to drop is not an act: a person who clicked twice is told there is no file and the journal
     * holds one line.
     */
    #[Test]
    public function nothingToDropAnnouncesNothing(): void
    {
        // Given
        $events = new RecordingEventDispatcher();

        // When
        $dropped = self::dropping(new InMemoryPersonalArchiveRepository(), $events)->droppedBy(Fixtures::user(), Fixtures::context());

        // Then
        static::assertFalse($dropped);
        static::assertSame([], $events->events);
    }

    /**
     * What is dropped is the request and not a file: a build on its way to a row that went away under it
     * finds none and writes nothing, which is what makes a request something a person can take back.
     */
    #[Test]
    public function aRequestStillBeingBuiltIsDropped(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archives->save(PersonalArchive::asked(Uuid::v7(), $user, Fixtures::now()));

        // When
        $dropped = self::dropping($archives)->droppedBy($user, Fixtures::context());

        // Then
        static::assertTrue($dropped);
        static::assertSame(0, $archives->count());
    }

    #[Test]
    public function droppingARequestStillBeingBuiltAnnouncesTheAct(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = PersonalArchive::asked(Uuid::v7(), $user, Fixtures::now());
        $archives->save($archive);
        $events = new RecordingEventDispatcher();

        // When
        self::dropping($archives, $events)->droppedBy($user, Fixtures::context());

        // Then
        $announced = $events->of(PersonDroppedTheirArchive::class);
        static::assertCount(1, $announced);
        static::assertTrue($announced[0]->archiveId->equals($archive->id));
    }

    /**
     * The archive of another person is not refused here, it is not reachable from here: what is dropped is
     * the last archive of the person who asks.
     */
    #[Test]
    public function thePersonDropsTheirOwnFileAndNotAnother(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $ada = Fixtures::user($tenant, 'ada', 'ada-subject');
        $grace = Fixtures::user($tenant, 'grace', 'grace-subject');
        $archives = new InMemoryPersonalArchiveRepository();
        self::built($archives, $ada);

        // When
        $dropped = self::dropping($archives)->droppedBy($grace, Fixtures::context());

        // Then
        static::assertFalse($dropped);
        static::assertSame(1, $archives->count());
    }

    private static function built(InMemoryPersonalArchiveRepository $archives, User $user): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), $user, Fixtures::now());
        $archive->fill(self::DOCUMENT, Fixtures::now());
        $archives->save($archive);

        return $archive;
    }

    private static function dropping(
        InMemoryPersonalArchiveRepository $archives,
        ?RecordingEventDispatcher $events = null,
    ): ArchiveDisposal {
        return new ArchiveDisposal($archives, $events ?? new RecordingEventDispatcher(), new MockClock(Fixtures::now()));
    }
}
