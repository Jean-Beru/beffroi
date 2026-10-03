<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\SessionsChapter;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function array_keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #453: where a person is signed in, in the archive they ask for. The sessions open and not every
 * session there ever was: a session that has ended is never a place a person is signed in, and what the
 * acts of their history were is the journal, which is its own chapter.
 */
final class SessionsChapterTest extends TestCase
{
    #[Test]
    public function aSessionIsOnWhatItProvedWhenItWasOpenedAndWhereFrom(): void
    {
        // Given
        $session = Fixtures::session();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save($session);

        // When
        $lines = self::chapter($sessions)->of($session->user);

        // Then
        static::assertSame($session->id->toRfc4122(), $lines[0]['id']);
        static::assertSame($session->authenticationContextClass()->value, $lines[0]['acr']);
        static::assertSame($session->methodReferences(), $lines[0]['amr']);
        $from = $lines[0]['opened_from'];
        static::assertIsArray($from);
        static::assertSame(Fixtures::context()->ipAddress, $from['ip_address']);
    }

    #[Test]
    public function theLineOfASessionNamesTheSameFactsForEveryOne(): void
    {
        // Given
        $session = Fixtures::session();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save($session);

        // When
        $lines = self::chapter($sessions)->of($session->user);

        // Then
        static::assertSame(
            ['id', 'acr', 'amr', 'established_at', 'expires_at', 'last_seen_at', 'opened_from', 'last_seen_from'],
            array_keys($lines[0]),
        );
    }

    #[Test]
    public function aSessionThatHasEndedIsNotInTheChapter(): void
    {
        // Given
        $session = Fixtures::session();
        $session->end(SessionEnd::RelyingParty, Fixtures::now());
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save($session);

        // When / Then
        static::assertSame([], self::chapter($sessions)->of($session->user));
    }

    #[Test]
    public function aPersonSignedInNowhereHasAnEmptyChapter(): void
    {
        // When / Then
        static::assertSame([], self::chapter(new InMemoryAuthenticationSessionRepository())->of(Fixtures::user()));
    }

    private static function chapter(InMemoryAuthenticationSessionRepository $sessions): SessionsChapter
    {
        return new SessionsChapter($sessions, new MockClock(Fixtures::now()));
    }
}
