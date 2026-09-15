<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class SessionTerminatorTest extends TestCase
{
    #[Test]
    public function itEndsOneSessionSavesItAndAnnouncesItOnce(): void
    {
        $alice = Fixtures::user();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $kept = Fixtures::session($alice);
        $ended = Fixtures::session($alice);
        $sessions->save($kept);
        $sessions->save($ended);
        $events = new RecordingEventDispatcher();
        $clock = new MockClock('2026-09-15T13:00:00+00:00');
        $terminator = new SessionTerminator($sessions, $clock, $events);
        $context = Fixtures::context($clock->now(), '198.51.100.7');
        $savesBefore = $sessions->saves;

        $terminator->end($ended, SessionEnd::User, $context);
        $terminator->end($ended, SessionEnd::Administrator, $context);

        static::assertTrue($ended->hasEnded());
        static::assertSame($savesBefore + 1, $sessions->saves);
        static::assertSame(SessionEnd::User, $ended->endedBy);
        static::assertEquals($clock->now(), $ended->endedAt);
        static::assertSame([$kept], $sessions->findActiveByUser($alice, $clock->now()));
        static::assertCount(1, $events->events);
        $event = $events->of(AuthenticationSessionEnded::class)[0];
        static::assertSame($ended, $event->session);
        static::assertSame($context, $event->context);
        static::assertEquals($clock->now(), $event->occurredAt);
    }
}
