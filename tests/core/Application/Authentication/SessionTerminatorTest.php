<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class SessionTerminatorTest extends TestCase
{
    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private AuthenticationSession $kept;

    private AuthenticationSession $ended;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private SessionTerminator $terminator;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->kept = Fixtures::session($this->alice);
        $this->ended = Fixtures::session($this->alice);
        $this->sessions->save($this->kept);
        $this->sessions->save($this->ended);
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now(), '198.51.100.7');
        $this->terminator = new SessionTerminator($this->sessions, $this->clock, $this->events);
    }

    #[Test]
    public function itEndsTheSessionNow(): void
    {
        // When
        $this->terminator->end($this->ended, SessionEnd::User, $this->context);

        // Then
        static::assertTrue($this->ended->hasEnded());
        static::assertSame(SessionEnd::User, $this->ended->endedBy);
        static::assertEquals($this->clock->now(), $this->ended->endedAt);
    }

    #[Test]
    public function itSavesTheEndedSessionAndLeavesTheOthersActive(): void
    {
        // Given
        $savesBefore = $this->sessions->saves;

        // When
        $this->terminator->end($this->ended, SessionEnd::User, $this->context);

        // Then
        static::assertSame($savesBefore + 1, $this->sessions->saves);
        static::assertSame([$this->kept], $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function itAnnouncesTheEndWithTheContextOfTheRequest(): void
    {
        // When
        $this->terminator->end($this->ended, SessionEnd::User, $this->context);

        // Then
        static::assertCount(1, $this->events->events);
        $event = $this->events->of(AuthenticationSessionEnded::class)[0];
        static::assertSame($this->ended, $event->session);
        static::assertSame($this->context, $event->context);
        static::assertEquals($this->clock->now(), $event->occurredAt);
    }

    #[Test]
    public function endingAnEndedSessionAgainChangesNothing(): void
    {
        // Given
        $this->terminator->end($this->ended, SessionEnd::User, $this->context);
        $savesBefore = $this->sessions->saves;

        // When
        $this->terminator->end($this->ended, SessionEnd::Administrator, $this->context);

        // Then
        static::assertSame(SessionEnd::User, $this->ended->endedBy);
        static::assertSame($savesBefore, $this->sessions->saves);
        static::assertCount(1, $this->events->events);
    }
}
