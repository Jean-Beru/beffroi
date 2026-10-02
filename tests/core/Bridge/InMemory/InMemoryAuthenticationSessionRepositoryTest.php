<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\Null\NullGeoLocator;
use Beffroi\Core\Bridge\Null\NullUserAgentParser;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryAuthenticationSessionRepositoryTest extends TestCase
{
    #[Test]
    public function itListsTheActiveSessionsOfAUserOnly(): void
    {
        // Given
        $alice = Fixtures::user();
        $repository = new InMemoryAuthenticationSessionRepository();
        $active = Fixtures::session($alice);
        $ended = Fixtures::session($alice);
        $ended->end(SessionEnd::User, Fixtures::now());
        $expired = Fixtures::session($alice, Fixtures::now()->modify('-2 days'));
        foreach ([$active, $ended, $expired, Fixtures::session(Fixtures::user(username: 'bob', subject: 'bob-subject'))] as $session) {
            $repository->save($session);
        }

        // When
        $sessions = $repository->findActiveByUser($alice, Fixtures::now());

        // Then
        static::assertSame([$active], $sessions);
    }

    #[Test]
    public function itFindsAnySavedSessionById(): void
    {
        // Given
        $repository = new InMemoryAuthenticationSessionRepository();
        $ended = Fixtures::session();
        $ended->end(SessionEnd::User, Fixtures::now());
        $repository->save($ended);

        // When / Then
        static::assertSame($ended, $repository->find($ended->id));
    }

    #[Test]
    public function itFindsNothingForAnUnknownId(): void
    {
        // Given
        $repository = new InMemoryAuthenticationSessionRepository();

        // When / Then
        static::assertNull($repository->find(Uuid::v7()));
    }

    #[Test]
    public function theNullGeoLocatorLocatesNothing(): void
    {
        // When / Then
        static::assertNull(new NullGeoLocator()->locate('203.0.113.10'));
    }

    #[Test]
    public function theNullUserAgentParserParsesNothing(): void
    {
        // When / Then
        static::assertNull(new NullUserAgentParser()->parse('curl/8.0'));
    }
}
