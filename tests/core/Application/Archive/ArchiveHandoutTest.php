<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive;

use Beffroi\Core\Application\Archive\ArchiveHandout;
use Beffroi\Core\Bridge\InMemory\InMemoryPersonalArchiveRepository;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Event\PersonTookTheirArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the archive is handed to the person who asked for it and to nobody else. There is no
 * identifier to pass, so the refusal that matters most in this issue is one no caller can forget to write.
 */
final class ArchiveHandoutTest extends TestCase
{
    private const string DOCUMENT = '{"profile":[]}';

    #[Test]
    public function thePersonWhoAskedIsGivenTheirArchive(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::built($archives, $user);

        // When
        $given = self::handing($archives)->givenTo($user, Fixtures::context());

        // Then
        static::assertSame($archive, $given);
    }

    /**
     * The act that matters most of the three: a file holding everything this provider knows of somebody
     * left it, and the journal says when and from where.
     */
    #[Test]
    public function givingTheArchiveAnnouncesTheAct(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::built($archives, $user);
        $events = new RecordingEventDispatcher();

        // When
        self::handing($archives, $events)->givenTo($user, Fixtures::context());

        // Then
        $announced = $events->of(PersonTookTheirArchive::class);
        static::assertCount(1, $announced);
        static::assertTrue($announced[0]->archiveId->equals($archive->id));
    }

    #[Test]
    public function aPersonWhoNeverAskedIsGivenNothing(): void
    {
        // Given
        $user = Fixtures::user();

        // When / Then
        static::assertNull(self::handing(new InMemoryPersonalArchiveRepository())->givenTo($user, Fixtures::context()));
    }

    #[Test]
    public function anArchiveStillBeingBuiltIsNotGiven(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archives->save(PersonalArchive::asked(Uuid::v7(), $user, Fixtures::now()));

        // When / Then
        static::assertNull(self::handing($archives)->givenTo($user, Fixtures::context()));
    }

    #[Test]
    public function anArchiveThatHasExpiredIsNotGiven(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $archive = self::built($archives, $user);

        // When / Then
        static::assertNull(self::handing($archives, at: $archive->expiresAt)->givenTo($user, Fixtures::context()));
    }

    /**
     * Nothing to give announces nothing: a page that was opened is not an archive that left.
     */
    #[Test]
    public function nothingToGiveAnnouncesNothing(): void
    {
        // Given
        $events = new RecordingEventDispatcher();

        // When
        self::handing(new InMemoryPersonalArchiveRepository(), $events)->givenTo(Fixtures::user(), Fixtures::context());

        // Then
        static::assertSame([], $events->events);
    }

    /**
     * The archive of another person is not refused here, it is not reachable from here: what is read is
     * the last archive of the person who asks.
     */
    #[Test]
    public function thePersonIsGivenTheirOwnArchiveAndNotAnother(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $ada = Fixtures::user($tenant, 'ada', 'ada-subject');
        $grace = Fixtures::user($tenant, 'grace', 'grace-subject');
        $archives = new InMemoryPersonalArchiveRepository();
        self::built($archives, $ada);

        // When / Then
        static::assertNull(self::handing($archives)->givenTo($grace, Fixtures::context()));
    }

    private static function built(InMemoryPersonalArchiveRepository $archives, User $user): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), $user, Fixtures::now());
        $archive->fill(self::DOCUMENT, Fixtures::now());
        $archives->save($archive);

        return $archive;
    }

    private static function handing(
        InMemoryPersonalArchiveRepository $archives,
        ?RecordingEventDispatcher $events = null,
        ?DateTimeImmutable $at = null,
    ): ArchiveHandout {
        return new ArchiveHandout($archives, $events ?? new RecordingEventDispatcher(), new MockClock($at ?? Fixtures::now()));
    }
}
