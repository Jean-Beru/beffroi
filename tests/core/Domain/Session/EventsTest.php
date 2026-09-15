<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EventsTest extends TestCase
{
    /**
     * Architecture §3.5: every event says when, in which tenant and from which request.
     */
    #[Test]
    public function userAuthenticatedCarriesTheContextOfTheSession(): void
    {
        $session = Fixtures::session();
        $event = new UserAuthenticated($session);

        static::assertSame($session->establishedAt, $event->occurredAt);
        static::assertSame($session->tenant, $event->tenant);
        static::assertSame($session->createdFrom, $event->context);
    }

    #[Test]
    public function sessionEndedCarriesTheContextOfTheRequestThatEndedIt(): void
    {
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+1 hour');
        $context = Fixtures::context($later, '198.51.100.7');
        $session->end(SessionEnd::RelyingParty, $later);

        $event = new AuthenticationSessionEnded($session, $later, $context);

        static::assertSame(SessionEnd::RelyingParty, $event->endedBy);
        static::assertSame($context, $event->context);
        static::assertSame($session->tenant, $event->tenant);
    }

    #[Test]
    public function sessionEndedRequiresAnEndedSession(): void
    {
        $this->expectException(LogicException::class);

        new AuthenticationSessionEnded(Fixtures::session(), Fixtures::now(), Fixtures::context());
    }
}
