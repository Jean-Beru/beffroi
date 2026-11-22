<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive;

use Beffroi\Core\Application\Archive\ArchiveRequest;
use Beffroi\Core\Bridge\InMemory\InMemoryPersonalArchiveRepository;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Event\PersonAskedForTheirArchive;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use function sprintf;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

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
    public function askingAgainOnceTheBuildDidNotComeBackStartsANewOne(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        $first = self::asking($archives)->askedBy($user, Fixtures::context());

        // When
        $again = self::asking($archives, at: self::afterTheDelay())->askedBy($user, Fixtures::context());

        // Then
        static::assertFalse($again->id->equals($first->id));
        static::assertFalse($again->isReady());
    }

    #[Test]
    public function askingAgainOnceTheBuildDidNotComeBackTakesTheRowItReplaces(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        self::asking($archives)->askedBy($user, Fixtures::context());

        // When
        self::asking($archives, at: self::afterTheDelay())->askedBy($user, Fixtures::context());

        // Then
        static::assertSame(1, $archives->count());
    }

    #[Test]
    public function askingAgainOnceTheBuildDidNotComeBackAnnouncesTheAct(): void
    {
        // Given
        $user = Fixtures::user();
        $archives = new InMemoryPersonalArchiveRepository();
        self::asking($archives)->askedBy($user, Fixtures::context());
        $events = new RecordingEventDispatcher();

        // When
        $again = self::asking($archives, $events, self::afterTheDelay())->askedBy($user, Fixtures::context());

        // Then
        $announced = $events->of(PersonAskedForTheirArchive::class);
        static::assertCount(1, $announced);
        static::assertTrue($announced[0]->archiveId->equals($again->id));
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

    private static function afterTheDelay(): DateTimeImmutable
    {
        return Fixtures::now()->modify(sprintf('+%d minutes', PersonalArchive::BUILT_WITHIN_MINUTES));
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
