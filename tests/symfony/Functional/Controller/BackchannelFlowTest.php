<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Beffroi\Bundle\Message\SendClientNotification;
use Beffroi\Bundle\Message\TellUserOfPendingApproval;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Transport\TransportInterface;

/**
 * CIBA Core and BCP 10027 over HTTP, end to end: a client asks for a user it names, that user finds the
 * request on a page of the provider and answers it, and the client comes back to the token endpoint for
 * what it was waiting on. One step per test.
 */
final class BackchannelFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'terminal-app';

    private const string SECRET = 'terminal-secret-of-at-least-32-characters';

    private const string PINGED_CLIENT_ID = 'pinged-terminal';

    private const string PINGED_SECRET = 'pinged-secret-of-at-least-32-characters!';

    private const string NOTIFICATION_TOKEN = 'a8f2c1d0e9b7a6c5d4e3f2a1b0';

    private const string PASSWORD = 'correct horse battery staple';

    /**
     * §7.3: the identifier, the lifetime and the interval, and no token anywhere.
     */
    #[Test]
    public function aClientIsAnsweredAnIdentifierALifetimeAndAnInterval(): void
    {
        // When
        $this->ask();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $parameters = self::json($response);
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', self::string($parameters['auth_req_id']));
        static::assertSame(300, $parameters['expires_in']);
        static::assertSame(5, $parameters['interval']);
        static::assertArrayNotHasKey('access_token', $parameters);
    }

    /**
     * §7.3: the identifier is a credential of one use and no cache holds it.
     */
    #[Test]
    public function theAnswerIsNeverCached(): void
    {
        // When
        $this->ask();

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    /**
     * §7: the user the request names is told that something is waiting for them, on the lane and not in
     * the request the client is waiting on.
     */
    #[Test]
    public function theUserIsToldOnTheLane(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);

        // When
        $this->ask();

        // Then
        $queued = self::queued();
        static::assertCount(1, $queued);
        static::assertInstanceOf(TellUserOfPendingApproval::class, $queued[0]->getMessage());
    }

    /**
     * §11: while the user has not answered, the client is told "not yet" and nothing else.
     */
    #[Test]
    public function aRequestNobodyAnsweredIsPending(): void
    {
        // Given
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        $this->come($authRequestId);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('authorization_pending', self::json($response)['error']);
    }

    /**
     * §11: a client asking faster than the interval it was given is told to slow down.
     */
    #[Test]
    public function aRequestFasterThanTheIntervalIsToldToSlowDown(): void
    {
        // Given
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);
        $this->come($authRequestId);

        // When
        $this->come($authRequestId);

        // Then
        static::assertSame('slow_down', self::json($this->browser->getResponse())['error']);
    }

    /**
     * §11: an identifier past its lifetime grants nothing.
     */
    #[Test]
    public function aRequestAfterTheLifetimeIsToldItExpired(): void
    {
        // Given
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        self::mockTime('+301 seconds');
        $this->come($authRequestId);

        // Then
        static::assertSame('expired_token', self::json($this->browser->getResponse())['error']);
    }

    /**
     * BCP 10027 §5.2: what is waiting is found by who is signed in, with the provider that is asking, the
     * client that asked, the message it wrote and every scope of the request.
     */
    #[Test]
    public function thePageNamesTheRequestAndWhatItAsksFor(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->ask([
            'binding_message' => 'Payment of 42 euros',
        ]);
        $this->signIn($alice);

        // When
        $crawler = $this->browser->request('GET', '/account/approvals');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString('Payment terminal at the counter', $crawler->filter('body')->text());
        static::assertSame(['Payment of 42 euros'], $crawler->filter('p[data-binding-message]')->extract(['data-binding-message']));
        static::assertSame(
            'Payment terminal at the counter says: Payment of 42 euros',
            $crawler->filter('p[data-binding-message]')->text(),
            'BCP 10027 section 5.2: the message names the client that wrote it',
        );
        static::assertSame(['openid', 'profile'], $crawler->filter('li[data-scope]')->extract(['data-scope']));
        static::assertSame(['op.test'], $crawler->filter('p[data-provider]')->extract(['data-provider']), 'BCP 10027 section 5.2: which provider is asking');
        static::assertCount(1, $crawler->filter('p[data-origin]'));
        static::assertCount(1, $crawler->filter('p[data-warning="unexpected"]'), 'BCP 10027 section 5.2: somebody who started nothing is told to refuse');
    }

    /**
     * §7.1: a request made for somebody else is waiting for nobody here.
     */
    #[Test]
    public function aRequestOfSomebodyElseIsNotInTheList(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->ask();
        $this->signIn(self::userWithPassword('bob', self::PASSWORD));

        // When
        $crawler = $this->browser->request('GET', '/account/approvals');

        // Then
        static::assertCount(1, $crawler->filter('p[data-approvals="none"]'));
        static::assertCount(0, $crawler->filter('section[data-approval]'));
    }

    /**
     * Architecture §5.2: the page offers the way back to the home of the account, whether the browser
     * reached it from there or from a notification, so that a user who answered, or who had nothing to
     * answer, is not left on a page with no way out.
     */
    #[Test]
    public function thePageOffersTheWayBackToTheHomeOfTheAccount(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $crawler = $this->browser->request('GET', '/account/approvals');

        // Then
        static::assertSame('/account', $crawler->filter('nav a[data-back]')->attr('href'));
    }

    /**
     * The page needs a signed-in user, and brings the browser back to it once the login is done.
     */
    #[Test]
    public function thePageAsksForALoginFirst(): void
    {
        // When
        $this->browser->request('GET', '/account/approvals');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login', $response->headers->get('Location'));
    }

    /**
     * §10.1: the whole flow. The user approves, and the client that comes back gets its tokens, the ones
     * of an authorization and nothing new.
     */
    #[Test]
    public function anApprovedRequestReleasesTheTokensToTheClient(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);
        $this->signIn($alice);
        $this->answer('Allow');

        // When
        self::mockTime('+5 seconds');
        $this->come($authRequestId);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $tokens = self::json($response);
        static::assertIsString($tokens['access_token']);
        static::assertIsString($tokens['id_token']);
        static::assertIsString($tokens['refresh_token']);
        static::assertSame('openid profile', $tokens['scope']);
        $claims = self::claimsOf(self::string($tokens['id_token']));
        static::assertSame('https://op.test', $claims['iss']);
        static::assertSame(self::CLIENT_ID, $claims['aud']);
    }

    /**
     * §11: a user who refuses ends the request, and the client learns it rather than waiting on.
     */
    #[Test]
    public function aRefusalEndsTheRequestAndTheClientLearnsIt(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);
        $this->signIn($alice);
        $this->answer('Refuse');

        // When
        self::mockTime('+10 seconds');
        $this->come($authRequestId);

        // Then
        static::assertSame('access_denied', self::json($this->browser->getResponse())['error']);
    }

    /**
     * §10.1: an identifier is spent once, and presented again is worth nothing.
     */
    #[Test]
    public function anIdentifierSpentOnceIsRefusedAfterThat(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);
        $this->signIn($alice);
        $this->answer('Allow');
        self::mockTime('+10 seconds');
        $this->come($authRequestId);

        // When
        self::mockTime('+20 seconds');
        $this->come($authRequestId);

        // Then
        static::assertSame('invalid_grant', self::json($this->browser->getResponse())['error']);
    }

    /**
     * BCP 10027 §5.2: a request is answered once, and the page then has nothing left to answer.
     */
    #[Test]
    public function aRequestIsAnsweredOnce(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->ask();
        $this->signIn($alice);
        $this->answer('Allow');

        // When
        $crawler = $this->browser->request('GET', '/account/approvals');

        // Then
        static::assertCount(1, $crawler->filter('p[data-approvals="none"]'));
    }

    /**
     * §10.2: a client that registered to be called back is told that the request is over, on the lane,
     * and comes to the token endpoint for the tokens like a poller.
     */
    #[Test]
    public function aPingedClientIsToldOnTheLaneAndComesForItsTokens(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->askToBeCalledBack())['auth_req_id']);
        $this->signIn($alice);
        self::queued();

        // When
        $this->answer('Allow');

        // Then
        $queued = self::queued();
        static::assertCount(1, $queued);
        $message = $queued[0]->getMessage();
        static::assertInstanceOf(SendClientNotification::class, $message);
        static::assertSame('https://terminal.test/ciba', $message->notificationEndpoint);
        static::assertSame($authRequestId, $message->authRequestId, 'CIBA Core section 10.2: the identifier the client was handed');
        static::assertSame(self::NOTIFICATION_TOKEN, $message->notificationToken);
    }

    /**
     * §10.2, §11: a client that registered to be called back comes when it is told, which is sooner than
     * the interval it was given to poll at, and the one request it makes then is answered. "slow_down"
     * is a variant of "authorization_pending" and says nothing about a request that has an answer.
     */
    #[Test]
    public function aPingedClientIsServedOnTheRequestItMakesWhenItIsCalledBack(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->askToBeCalledBack())['auth_req_id']);
        $this->comeCalledBack($authRequestId);
        $this->signIn($alice);
        $this->answer('Allow');

        // When
        $this->comeCalledBack($authRequestId);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['access_token']);
    }

    /**
     * §10.2, §11: the refusal is on the same clock as the acceptance, a client called back about a
     * request the user ended being told that they ended it.
     */
    #[Test]
    public function aPingedClientCalledBackOnARefusalIsToldTheUserRefused(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $authRequestId = self::string(self::json($this->askToBeCalledBack())['auth_req_id']);
        $this->comeCalledBack($authRequestId);
        $this->signIn($alice);
        $this->answer('Refuse');

        // When
        $this->comeCalledBack($authRequestId);

        // Then
        static::assertSame('access_denied', self::json($this->browser->getResponse())['error']);
    }

    /**
     * §7.1: a request that names no user, or names two, is refused.
     */
    #[Test]
    public function aRequestThatDoesNotNameItsUserOnceIsRefused(): void
    {
        // When
        $this->ask([
            'id_token_hint' => 'eyJ.the.token',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_request', self::json($response)['error']);
    }

    /**
     * Decision 0006, §13: a request naming a stranger is answered exactly as every other one, and the
     * client then waits for an answer that never comes.
     */
    #[Test]
    public function aRequestNamingAStrangerIsAnsweredLikeEveryOther(): void
    {
        // Given
        $asked = $this->ask([
            'login_hint' => 'nobody-subject',
        ]);
        $answer = self::json($asked);

        // When
        $this->come(self::string($answer['auth_req_id']));

        // Then
        static::assertSame(Response::HTTP_OK, $asked->getStatusCode());
        static::assertSame(300, $answer['expires_in']);
        static::assertSame('authorization_pending', self::json($this->browser->getResponse())['error'], 'it waits for an answer that never comes');
    }

    /**
     * @param array<string, string> $overrides
     */
    private function ask(array $overrides = []): Response
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/backchannel_authentication',
            [
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
                ...$overrides,
            ],
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );

        return $this->browser->getResponse();
    }

    /**
     * A request of the client that registered to be called back (§7.1): it sends the token the provider
     * will present back to it.
     */
    private function askToBeCalledBack(): Response
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/backchannel_authentication',
            [
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
                'client_notification_token' => self::NOTIFICATION_TOKEN,
            ],
            server: self::credentials(self::PINGED_CLIENT_ID, self::PINGED_SECRET),
        );

        return $this->browser->getResponse();
    }

    private function comeCalledBack(string $authRequestId): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:openid:params:grant-type:ciba',
                'auth_req_id' => $authRequestId,
            ],
            server: self::credentials(self::PINGED_CLIENT_ID, self::PINGED_SECRET),
        );
    }

    private function come(string $authRequestId): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:openid:params:grant-type:ciba',
                'auth_req_id' => $authRequestId,
            ],
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );
    }

    private function answer(string $button): void
    {
        $crawler = $this->browser->request('GET', '/account/approvals');
        $this->browser->submit($crawler->selectButton($button)->form());
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
     * @return array<string, string>
     */
    private static function credentials(string $clientId, string $secret): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
        ];
    }
}
