<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §5.2: every session of a person but the one they are reading from, ended in one act.
 */
final class OtherSessionsTerminationTest extends TestCase
{
    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private AuthenticationSession $kept;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private OtherSessionsTermination $termination;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->kept = Fixtures::session($this->alice);
        $this->sessions->save($this->kept);
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->termination = new OtherSessionsTermination(
            $this->sessions,
            new SessionTerminator($this->sessions, $this->clock, $this->events),
        );
    }

    #[Test]
    public function everySessionButTheOneKeptIsEnded(): void
    {
        // Given
        $elsewhere = $this->alsoSignedIn();
        $again = $this->alsoSignedIn();

        // When
        $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now()));

        // Then
        static::assertTrue($elsewhere->hasEnded());
        static::assertTrue($again->hasEnded());
        static::assertFalse($this->kept->hasEnded());
    }

    /**
     * Decision 0031: reaching its expiry ended nothing, so what was issued under a session past it lives
     * on, and the session is ended with the others for that to be taken back with theirs.
     */
    #[Test]
    public function aSessionPastItsExpiryIsEndedAsWell(): void
    {
        // Given
        $expired = Fixtures::session($this->alice, $this->clock->now()->modify('-13 hours'));
        $this->sessions->save($expired);

        // When
        $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(SessionEnd::User, $expired->endedBy);
    }

    /**
     * The person reading the page is not signed out by the button that signs out everything else.
     */
    #[Test]
    public function itSaysHowManyItEnded(): void
    {
        // Given
        $this->alsoSignedIn();
        $this->alsoSignedIn();

        // When / Then
        static::assertSame(2, $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now())));
    }

    /**
     * Each one leaves the trace every ended session leaves, which is what reaches the relying parties it
     * opened for: a statement that closed them all at once would be the one end nobody is told about.
     */
    #[Test]
    public function eachEndIsAnnouncedAsTheEndOfASession(): void
    {
        // Given
        $elsewhere = $this->alsoSignedIn();

        // When
        $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now()));

        // Then
        $announced = $this->events->of(AuthenticationSessionEnded::class);
        static::assertCount(1, $announced);
        static::assertSame($elsewhere, $announced[0]->session);
        static::assertSame(SessionEnd::User, $elsewhere->endedBy);
    }

    /**
     * A person signed in nowhere else has nothing ended and nothing announced.
     */
    #[Test]
    public function aPersonSignedInNowhereElseHasNothingEnded(): void
    {
        // When
        $ended = $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(0, $ended);
        static::assertSame([], $this->events->events);
    }

    /**
     * The sessions of another person are not this person's to end: what is read is what is open in the
     * name of the one whose session is kept.
     */
    #[Test]
    public function theSessionsOfSomebodyElseAreLeftAlone(): void
    {
        // Given
        $grace = Fixtures::user($this->alice->tenant, 'grace', 'grace-subject');
        $hers = Fixtures::session($grace, $this->clock->now());
        $this->sessions->save($hers);

        // When
        $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now()));

        // Then
        static::assertFalse($hers->hasEnded());
    }

    private function alsoSignedIn(): AuthenticationSession
    {
        $session = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($session);

        return $session;
    }
}
