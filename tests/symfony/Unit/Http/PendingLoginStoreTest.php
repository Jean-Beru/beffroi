<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\PendingLoginStore;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.4: the login held between its two steps lives in the HTTP session, one at a time, until
 * a code completes it. What it holds it hands back as it is: whether a held login has run out of time is
 * a refusal of the second step, which the core pronounces for both paths (issue #130), so a store that
 * judged it would be the second place that decides what a login is.
 */
final class PendingLoginStoreTest extends TestCase
{
    private Session $session;

    private PendingLoginStore $store;

    private DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->session = new Session(new MockArraySessionStorage());
        $this->store = new PendingLoginStore();
        $this->now = new DateTimeImmutable('2026-09-20T10:00:00+00:00');
    }

    #[Test]
    public function theLoginHeldIsHandedBack(): void
    {
        // Given
        $login = PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now);
        $this->store->hold($this->session, $login);

        // When / Then
        static::assertSame($login, $this->store->held($this->session));
    }

    /**
     * The one past its lifetime is handed back too, and the core refuses it: a browser that was late is
     * answered as the use case answers it, and the act is written in that person's journal.
     */
    #[Test]
    public function anExpiredLoginIsHandedBackAllTheSame(): void
    {
        // Given
        $login = PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now->modify('-10 minutes'));
        $this->store->hold($this->session, $login);

        // When / Then
        static::assertTrue($login->isExpired($this->now));
        static::assertSame($login, $this->store->held($this->session));
    }

    #[Test]
    public function nothingIsHeldWhenNothingWasHeld(): void
    {
        // When / Then
        static::assertNull($this->store->held($this->session));
    }

    #[Test]
    public function theNewerLoginReplacesTheOlder(): void
    {
        // Given
        $this->store->hold($this->session, PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now));
        $newer = PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now->modify('+1 minute'));

        // When
        $this->store->hold($this->session, $newer);

        // Then
        static::assertSame($newer, $this->store->held($this->session));
    }

    #[Test]
    public function aForgottenLoginIsHeldNoLonger(): void
    {
        // Given
        $this->store->hold($this->session, PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now));

        // When
        $this->store->forget($this->session);

        // Then
        static::assertNull($this->store->held($this->session));
    }

    #[Test]
    public function somethingElseUnderTheKeyIsNotALogin(): void
    {
        // Given
        $this->session->set(PendingLoginStore::KEY, 'not a login');

        // When / Then
        static::assertNull($this->store->held($this->session));
    }
}
