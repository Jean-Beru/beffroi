<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive;

use Beffroi\Core\Application\Archive\ArchiveRequest;
use Beffroi\Core\Bridge\InMemory\InMemoryPersonalArchiveRepository;
use Beffroi\Core\Domain\Event\PersonAskedForTheirArchive;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #453: a person asks for everything this provider holds about them, and the request that asks
 * builds nothing. It writes a row, says the act happened, and the archive is assembled off the request.
 */
final class ArchiveRequestTest extends TestCase
{
    #[Test]
    public function askingWritesARowAndBuildsNothing(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();

        // When
        $archive = self::asking($archives)->askedBy($user, Fixtures::context());

        // Then
        static::assertFalse($archive->isReady());
        static::assertSame($archive, $archives->latestOf($user));
    }

    /**
     * The act is what builds the archive: a handler of the integration listens for it, so the page that
     * was clicked dispatches nothing of its own.
     */
    #[Test]
    public function askingAnnouncesTheActWithTheIdentifierOfTheArchive(): void
    {
        // Given
        $user = Fixtures::user();
        $events = new RecordingEventDispatcher();

        // When
        $archive = self::asking(events: $events)->askedBy($user, Fixtures::context());

        // Then
        $announced = $events->of(PersonAskedForTheirArchive::class);
        static::assertCount(1, $announced);
        static::assertTrue($announced[0]->archiveId->equals($archive->id));
        static::assertSame($user->subject->value, $announced[0]->person->value);
    }

    /**
     * A second click is not a second build, and nobody fills a queue by holding a button.
     */
    #[Test]
    public function askingAgainWhileOneIsBeingBuiltGivesThatOneBack(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $first = self::asking($archives)->askedBy($user, Fixtures::context());

        // When
        $again = self::asking($archives)->askedBy($user, Fixtures::context());

        // Then
        static::assertSame($first, $again);
        static::assertSame(1, $archives->count());
    }

    #[Test]
    public function askingAgainWhileOneIsBeingBuiltAnnouncesNothing(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        self::asking($archives)->askedBy($user, Fixtures::context());
        $events = new RecordingEventDispatcher();

        // When
        self::asking($archives, $events)->askedBy($user, Fixtures::context());

        // Then
        static::assertSame([], $events->of(PersonAskedForTheirArchive::class));
    }

    /**
     * What a person asks for is what this provider holds now, and a file built last Tuesday is not that.
     */
    #[Test]
    public function askingOnceOneIsReadyStartsANewOne(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $first = self::asking($archives)->askedBy($user, Fixtures::context());
        $first->fill('{"profile":[]}', Fixtures::now());

        // When
        $again = self::asking($archives)->askedBy($user, Fixtures::context());

        // Then
        static::assertFalse($again->id->equals($first->id));
        static::assertFalse($again->isReady());
    }

    #[Test]
    public function askingOnceTheLastOneHasExpiredStartsANewOne(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $first = self::asking($archives)->askedBy($user, Fixtures::context());

        // When
        $again = self::asking($archives, at: $first->expiresAt)->askedBy($user, Fixtures::context());

        // Then
        static::assertFalse($again->id->equals($first->id));
    }

    /**
     * What a person is offered is their last archive, so a second one asked for later is the one that
     * answers: a row of last Tuesday is not what they clicked for today.
     */
    #[Test]
    public function theLastArchiveIsTheOneAskedForLast(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $first = self::asking($archives)->askedBy($user, Fixtures::context());
        $first->fill('{"profile":[]}', Fixtures::now());
        $later = Fixtures::now()->modify('+1 hour');

        // When
        $again = self::asking($archives, at: $later)->askedBy($user, Fixtures::context());

        // Then
        static::assertSame($again, $archives->latestOf($user));
    }

    /**
     * The archive of one person is theirs: what a second person asks for is a row of their own.
     */
    #[Test]
    public function theArchiveOfOnePersonIsNotTheArchiveOfAnother(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $ada = Fixtures::user($tenant, 'ada', 'ada-subject');
        $grace = Fixtures::user($tenant, 'grace', 'grace-subject');
        $archives = new InMemoryPersonalArchiveRepository();

        // When
        $hers = self::asking($archives)->askedBy($ada, Fixtures::context());
        self::asking($archives)->askedBy($grace, Fixtures::context());

        // Then
        static::assertSame($hers, $archives->latestOf($ada));
    }

    private static function asking(
        ?InMemoryPersonalArchiveRepository $archives = null,
        ?RecordingEventDispatcher $events = null,
        ?DateTimeImmutable $at = null,
    ): ArchiveRequest {
        return new ArchiveRequest(
            $archives ?? new InMemoryPersonalArchiveRepository(),
            $events ?? new RecordingEventDispatcher(),
            new MockClock($at ?? Fixtures::now()),
        );
    }
}
