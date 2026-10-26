<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function array_column;
use function array_keys;
use Closure;
use Beffroi\Bundle\Http\LogoutTokenSender;
use Beffroi\Bundle\Message\SendLogoutToken;
use Beffroi\Bundle\MessageHandler\SendLogoutTokenHandler;
use Beffroi\Bundle\Messenger\NotificationNotDeliveredException;
use Beffroi\Bundle\Messenger\NotificationRetryPolicy;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Bundle\Tests\Functional\Messenger\LogoutEndpoints;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Transport\TransportInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Back-Channel Logout 1.0 §2.5 and §2.8, architecture §5.6: what the provider does with the logout token
 * it minted, and what it does when the relying party does not take it. The delivery is asynchronous in
 * production; the token waits in the queue of this kernel as it waits on a broker, and what a worker does
 * with it happens here on the call of the handler, or under the worker of the lane itself when what is
 * judged is how often the lane brings the token back.
 */
final class LogoutTokenDeliveryTest extends ConsoleTestCase
{
    private const string URI = 'https://demo.test/backchannel-logout';

    private const string SESSION = '0199a0f2-7c3e-7000-8000-0000000000a1';

    private const string TOKEN = 'eyJ0eXAiOiJsb2dvdXQrand0In0.eyJpc3MiOiJodHRwczovL29wLnRlc3QifQ.signature';

    private LogoutEndpoints $endpoints;

    protected function setUp(): void
    {
        $this->endpoints = new LogoutEndpoints([LogoutEndpoints::answering(200)]);
        parent::setUp();
    }

    protected function configureContainer(): Closure
    {
        return $this->endpoints->takeOver(...);
    }

    /**
     * Architecture §5.6: the logout answers the browser without waiting for the relying party. The token
     * waits in the queue of its own transport, and a client that hangs holds a worker, never a user.
     */
    #[Test]
    public function theLogoutAnswersWithoutWaitingForTheClient(): void
    {
        // Given
        $this->signedInWith('oidc-demo');

        // When
        $this->logOut();

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], $this->endpoints->requests);
        static::assertCount(1, self::queued());
    }

    /**
     * §2.5: the token reaches the URI the client registered, posted as a form whose one parameter is the
     * one of the section, and it names the session that ended.
     */
    #[Test]
    public function theQueuedTokenIsPostedToTheClient(): void
    {
        // Given
        $session = $this->signedInWith('oidc-demo');
        $this->logOut();

        // When
        $this->deliverQueued();

        // Then
        static::assertCount(1, $this->endpoints->requests);
        [$request] = $this->endpoints->requests;
        static::assertSame(self::URI, $request['url']);
        static::assertSame(['application/x-www-form-urlencoded'], $request['headers']['content-type'] ?? []);
        static::assertSame([LogoutTokenSender::PARAMETER], array_keys($request['parameters']));
        static::assertSame($session->id->toRfc4122(), self::claimsOf(self::string($request['parameters'][LogoutTokenSender::PARAMETER]))['sid']);
        static::assertSame([], self::givenUp());
    }

    /**
     * §2.8: a client that answers 200 is done, and nothing is given up on.
     */
    #[Test]
    public function aClientThatAnswersOkIsDone(): void
    {
        // When
        $this->deliver();

        // Then
        static::assertSame([self::URI], array_column($this->endpoints->requests, 'url'));
        static::assertSame([], self::givenUp());
    }

    /**
     * §2.8: a client that failed for its own reasons is asked again, which the transport does on the
     * schedule of its retry policy; nothing is given up on while it may still work.
     */
    #[Test]
    public function aClientThatFailsForItsOwnReasonsIsAskedAgain(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(500)]);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('the client answered 500');

        // When
        $this->deliver();
    }

    /**
     * The token of the second attempt is the one that was minted, and the client that came back takes it:
     * a retry asks the key management service for no new signature.
     */
    #[Test]
    public function aClientThatComesBackTakesTheSameTokenOnTheNextAttempt(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(500), LogoutEndpoints::answering(200)]);
        $message = self::message();
        try {
            self::handler()($message);
        } catch (NotificationNotDeliveredException) {
            // the first attempt, which the transport would bring back
        }

        // When
        self::handler()($message);

        // Then
        static::assertSame([self::TOKEN, self::TOKEN], array_column(array_column($this->endpoints->requests, 'parameters'), LogoutTokenSender::PARAMETER));
        static::assertSame([], self::givenUp());
    }

    /**
     * A client that never answers is asked again too: a timeout is not a refusal.
     */
    #[Test]
    public function aClientThatNeverAnswersIsAskedAgain(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::timingOut()]);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('the client cannot be reached');

        // When
        $this->deliver();
    }

    /**
     * §2.8, architecture §5.6: a client that never comes back is asked as many times as the policy of the
     * notifications lane allows, the first send and each of its retries, and then no more.
     */
    #[Test]
    public function aClientThatNeverComesBackIsAskedAsOftenAsTheLaneAllows(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(503)]);
        self::queue(self::message());

        // When
        self::work();

        // Then
        static::assertCount(self::policy()->attempts(), $this->endpoints->requests);
    }

    /**
     * §2.8: once the policy of the lane runs out, the provider says which client it gave up on and what the
     * last attempt got back, as it does for a client that refused.
     */
    #[Test]
    public function aClientTheLaneRunsOutOnIsGivenUpOn(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering(503)]);
        self::queue(self::message());

        // When
        self::work();

        // Then
        $events = self::givenUp();
        static::assertCount(1, $events);
        [$givenUp] = $events;
        static::assertSame('oidc-demo', $givenUp->clientId);
        static::assertStringContainsString('the client answered 503', $givenUp->reason);
    }

    /**
     * Decision 0006: no outbound request follows a redirect, and the same redirect would answer every
     * attempt, so the provider gives up at once and says where it was being sent.
     */
    #[Test]
    public function aClientThatRedirectsIsNotFollowedAndIsGivenUpOn(): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::redirectingTo('https://elsewhere.test/logout')]);

        // When
        $this->deliver();

        // Then
        static::assertSame([self::URI], array_column($this->endpoints->requests, 'url'));
        [$givenUp] = self::givenUp();
        static::assertStringContainsString('https://elsewhere.test/logout', $givenUp->reason);
        static::assertSame('oidc-demo', $givenUp->clientId);
    }

    /**
     * §2.8: 400 and 501 are the two answers that say the client read the token and will not act on it;
     * asking again gets the same answer, so the provider gives up and says so.
     */
    #[Test]
    #[DataProvider('provideFinalRefusals')]
    public function aClientThatRefusesTheTokenIsGivenUpOnAtOnce(int $status): void
    {
        // Given
        $this->endpoints->willAnswer([LogoutEndpoints::answering($status)]);

        // When
        $this->deliver();

        // Then
        static::assertCount(1, $this->endpoints->requests);
        [$givenUp] = self::givenUp();
        static::assertStringContainsString((string) $status, $givenUp->reason);
        static::assertSame(self::SESSION, $givenUp->sessionId->toRfc4122());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideFinalRefusals(): iterable
    {
        yield 'the request was invalid' => [400];
        yield 'the client does not implement the logout' => [501];
    }

    private function deliver(): void
    {
        self::handler()(self::message());
    }

    /**
     * The token put on the command bus as the provider puts it there, which routes it to the notifications
     * lane.
     */
    private static function queue(SendLogoutToken $message): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch($message);
    }

    /**
     * What the worker of a deployment does with the lane, "messenger:consume async_notifications", for the
     * whole schedule of the policy and as long again, where a lane that never gives up would still be
     * trying: the clock of the kernel is mocked, so the waits between two attempts pass without the test
     * sleeping. Nothing is reset between two messages, the queue of this kernel living in memory, where a
     * reset empties it.
     */
    private static function work(): void
    {
        self::mockTime();
        self::console('messenger:consume', [
            'receivers' => ['async_notifications'],
            '--time-limit' => (string) (2 * self::policy()->waiting()),
            '--no-reset' => null,
        ]);
    }

    private static function policy(): NotificationRetryPolicy
    {
        return self::service(NotificationRetryPolicy::class, NotificationRetryPolicy::class);
    }

    /**
     * What a worker does with what it finds in the queue.
     */
    private function deliverQueued(): void
    {
        foreach (self::queued() as $envelope) {
            $message = $envelope->getMessage();
            static::assertInstanceOf(SendLogoutToken::class, $message);
            self::handler()($message);
        }
    }

    /**
     * @return list<Envelope>
     */
    private static function queued(): array
    {
        $envelopes = [];
        foreach (self::service('test.beffroi.notification_queue', TransportInterface::class)->get() as $envelope) {
            static::assertInstanceOf(Envelope::class, $envelope);
            $envelopes[] = $envelope;
        }

        return $envelopes;
    }

    /**
     * The session of alice, signed in by one client through the whole code flow.
     */
    private function signedInWith(string $clientId): AuthenticationSession
    {
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient($clientId, 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        return $session;
    }

    private function logOut(): void
    {
        $this->browser->submit($this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
        ])->selectButton('Sign out')->form());
    }

    private static function message(): SendLogoutToken
    {
        return new SendLogoutToken(
            self::tenant(),
            'oidc-demo',
            self::URI,
            self::TOKEN,
            Uuid::fromString(self::SESSION),
            new Subject('alice-subject'),
            self::context(),
        );
    }

    private static function handler(): SendLogoutTokenHandler
    {
        return self::service('test.beffroi.logout_token_delivery', SendLogoutTokenHandler::class);
    }

    /**
     * @return list<LogoutTokenGivenUp>
     */
    private static function givenUp(): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LogoutTokenGivenUp) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
