<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use App\Message\AdvanceKeyLifecycle;
use App\Message\SendLogoutToken;
use App\Messenger\LogoutTokenGivenUpListener;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Event\WorkerMessageFailedEvent;
use Symfony\Component\Uid\Uuid;

/**
 * Back-Channel Logout 1.0 §2.8: the end of the retries of a logout token is an event, not a silence.
 */
final class LogoutTokenGivenUpListenerTest extends TestCase
{
    private const string SESSION = '0199a0f2-7c3e-7000-8000-0000000000a1';

    private RecordingEventDispatcher $events;

    private LogoutTokenGivenUpListener $listener;

    protected function setUp(): void
    {
        $this->events = new RecordingEventDispatcher();
        $this->listener = new LogoutTokenGivenUpListener($this->events, new MockClock(Fixtures::now()));
    }

    /**
     * The transport has brought the message back as many times as its policy allows: the provider says
     * which client was left believing its user is signed in, and why.
     */
    #[Test]
    public function aLogoutTokenTheTransportGivesUpOnIsAnnounced(): void
    {
        // When
        ($this->listener)(self::failure(self::message(), willRetry: false));

        // Then
        [$givenUp] = $this->events->of(LogoutTokenGivenUp::class);
        static::assertSame('oidc-demo', $givenUp->clientId);
        static::assertSame(self::SESSION, $givenUp->sessionId->toRfc4122());
        static::assertSame('the client answered 503', $givenUp->reason);
        static::assertSame(Fixtures::now()->getTimestamp(), $givenUp->occurredAt->getTimestamp());
    }

    /**
     * A failure the transport will bring back is not a giving up: nothing is announced while the client
     * may still take the token.
     */
    #[Test]
    public function aFailureThatWillBeTriedAgainIsNotAnnounced(): void
    {
        // When
        ($this->listener)(self::failure(self::message(), willRetry: true));

        // Then
        static::assertSame([], $this->events->of(LogoutTokenGivenUp::class));
    }

    /**
     * Another message that runs out of retries is another matter; this listener answers for one kind.
     */
    #[Test]
    public function aMessageOfAnotherKindIsNotAnnouncedAsALogout(): void
    {
        // When
        ($this->listener)(self::failure(new AdvanceKeyLifecycle(), willRetry: false));

        // Then
        static::assertSame([], $this->events->of(LogoutTokenGivenUp::class));
    }

    private static function message(): SendLogoutToken
    {
        return new SendLogoutToken(
            Fixtures::tenant(),
            'oidc-demo',
            'https://demo.test/backchannel-logout',
            'a.logout.token',
            Uuid::fromString(self::SESSION),
            Fixtures::user()->subject,
            Fixtures::context(),
        );
    }

    private static function failure(object $message, bool $willRetry): WorkerMessageFailedEvent
    {
        $event = new WorkerMessageFailedEvent(new Envelope($message), 'async_notifications', new RuntimeException('the client answered 503'));
        if ($willRetry) {
            $event->setForRetry();
        }

        return $event;
    }
}
