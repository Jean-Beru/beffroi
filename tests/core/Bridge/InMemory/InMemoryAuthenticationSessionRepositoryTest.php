<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\Null\NullGeoLocator;
use Heidi\Core\Bridge\Null\NullUserAgentParser;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryAuthenticationSessionRepositoryTest extends TestCase
{
    #[Test]
    public function itListsTheActiveSessionsOfAUserOnly(): void
    {
        $alice = Fixtures::user();
        $bob = Fixtures::user(username: 'bob', subject: 'bob-subject');
        $repository = new InMemoryAuthenticationSessionRepository();
        $active = Fixtures::session($alice);
        $ended = Fixtures::session($alice);
        $ended->end(SessionEnd::User, Fixtures::now());
        $expired = Fixtures::session($alice, Fixtures::now()->modify('-2 days'));
        foreach ([$active, $ended, $expired, Fixtures::session($bob)] as $session) {
            $repository->save($session);
        }

        static::assertSame([$active], $repository->findActiveByUser($alice, Fixtures::now()));
        static::assertSame($ended, $repository->find($ended->id));
        static::assertNull($repository->find(Uuid::v7()));
    }

    #[Test]
    public function theNullEnrichersEnrichNothing(): void
    {
        static::assertNull(new NullGeoLocator()->locate('203.0.113.10'));
        static::assertNull(new NullUserAgentParser()->parse('curl/8.0'));
    }
}
