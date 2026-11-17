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
 * Architecture §5.2
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
     * Decision 0031
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

    #[Test]
    public function itSaysHowManyItEnded(): void
    {
        // Given
        $this->alsoSignedIn();
        $this->alsoSignedIn();

        // When / Then
        static::assertSame(2, $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now())));
    }

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

    #[Test]
    public function aPersonSignedInNowhereElseHasNothingEnded(): void
    {
        // When
        $ended = $this->termination->endEveryOther($this->kept, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame(0, $ended);
        static::assertSame([], $this->events->events);
    }

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

    #[Test]
    public function everySessionOfThePersonEndsWhenNoneIsKept(): void
    {
        // Given
        $elsewhere = $this->alsoSignedIn();

        // When
        $ended = $this->termination->endEvery($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([2, true, true], [$ended, $this->kept->hasEnded(), $elsewhere->hasEnded()]);
    }

    private function alsoSignedIn(): AuthenticationSession
    {
        $session = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($session);

        return $session;
    }
}
