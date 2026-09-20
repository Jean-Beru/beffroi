<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use DateTimeImmutable;
use Heidi\Bundle\Http\PendingLoginStore;
use Heidi\Bundle\Security\PendingLogin;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.4: the login held between its two steps lives in the HTTP session, one at a time,
 * until a code completes it or it expires.
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
    public function theLoginHeldIsPendingUntilItExpires(): void
    {
        // Given
        $login = PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now);
        $this->store->hold($this->session, $login);

        // When
        $pending = $this->store->pending($this->session, $this->now->modify('+4 minutes 59 seconds'));

        // Then
        static::assertSame($login, $pending);
    }

    #[Test]
    public function anExpiredLoginIsForgotten(): void
    {
        // Given
        $this->store->hold($this->session, PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now));

        // When
        $pending = $this->store->pending($this->session, $this->now->modify('+5 minutes'));

        // Then
        static::assertNull($pending);
        static::assertFalse($this->session->has(PendingLoginStore::KEY));
    }

    #[Test]
    public function nothingIsPendingWhenNothingWasHeld(): void
    {
        // When / Then
        static::assertNull($this->store->pending($this->session, $this->now));
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
        static::assertSame($newer, $this->store->pending($this->session, $this->now->modify('+1 minute')));
    }

    #[Test]
    public function aForgottenLoginIsNotPending(): void
    {
        // Given
        $this->store->hold($this->session, PendingLogin::provenAt(Uuid::v7(), [AuthenticationMethod::password()], $this->now));

        // When
        $this->store->forget($this->session);

        // Then
        static::assertNull($this->store->pending($this->session, $this->now));
    }

    #[Test]
    public function somethingElseUnderTheKeyIsNotALogin(): void
    {
        // Given
        $this->session->set(PendingLoginStore::KEY, 'not a login');

        // When / Then
        static::assertNull($this->store->pending($this->session, $this->now));
    }
}
