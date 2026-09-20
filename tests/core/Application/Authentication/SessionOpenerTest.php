<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use DateInterval;
use Heidi\Core\Application\Authentication\SessionOpener;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class SessionOpenerTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private SessionOpener $opener;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-20T09:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now()->modify('-1 second'), '198.51.100.7');
        $this->opener = new SessionOpener($this->sessions, $this->clock, $this->events, new DateInterval('PT8H'));
    }

    #[Test]
    public function itOpensASessionOfTheUserInTheTenant(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertSame($this->tenant, $session->tenant);
        static::assertSame($this->alice, $session->user);
        static::assertSame($this->context, $session->createdFrom);
        static::assertFalse($session->hasEnded());
    }

    #[Test]
    public function itDatesTheSessionNowNotWhenTheRequestWasReceived(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertEquals($this->clock->now(), $session->establishedAt);
        static::assertEquals($this->clock->now(), $session->authenticatedAt());
    }

    #[Test]
    public function itProvesEveryMethodGivenAtOnce(): void
    {
        // Given
        $methods = [new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), new AuthenticationMethod(AuthenticationMethod::USER_PRESENCE)];

        // When
        $session = $this->opener->open($this->tenant, $this->alice, $methods, $this->context);

        // Then
        static::assertSame(['hwk', 'user'], $session->methodReferences());
        static::assertEquals($this->clock->now(), $session->proofs->provenAt($methods[0]));
        static::assertEquals($this->clock->now(), $session->proofs->provenAt($methods[1]));
    }

    #[Test]
    public function itExpiresTheSessionAfterTheLifetimeGiven(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+8 hours'), $session->expiresAt);
    }

    #[Test]
    public function theDefaultLifetimeIsTwelveHours(): void
    {
        // Given
        $opener = new SessionOpener($this->sessions, $this->clock, $this->events);

        // When
        $session = $opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+12 hours'), $session->expiresAt);
    }

    #[Test]
    public function itSavesTheSession(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertSame($session, $this->sessions->find($session->id));
    }

    #[Test]
    public function itAnnouncesTheAuthenticationOnce(): void
    {
        // When
        $session = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertCount(1, $this->events->events);
        static::assertInstanceOf(UserAuthenticated::class, $this->events->events[0]);
        static::assertSame($session, $this->events->events[0]->session);
    }

    #[Test]
    public function twoSessionsOpenedForTheSameUserAreDistinct(): void
    {
        // When
        $first = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);
        $second = $this->opener->open($this->tenant, $this->alice, [AuthenticationMethod::password()], $this->context);

        // Then
        static::assertFalse($first->id->equals($second->id));
        static::assertCount(2, $this->sessions->findActiveByUser($this->alice, $this->clock->now()));
    }

    #[Test]
    public function itRefusesAUserOfAnotherTenant(): void
    {
        // Given
        $bob = Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'), 'bob', 'bob-subject');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A session authenticates a user of its own tenant.');

        // When
        $this->opener->open($this->tenant, $bob, [AuthenticationMethod::password()], $this->context);
    }

    #[Test]
    public function nothingIsSavedNorAnnouncedForAUserOfAnotherTenant(): void
    {
        // Given
        $bob = Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'), 'bob', 'bob-subject');

        // When
        try {
            $this->opener->open($this->tenant, $bob, [AuthenticationMethod::password()], $this->context);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame([], $this->sessions->findActiveByUser($bob, $this->clock->now()));
        static::assertSame([], $this->events->events);
    }
}
