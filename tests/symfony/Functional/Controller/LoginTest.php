<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Core\Domain\Event\PasswordRehashed;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function sleep;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.4, the acceptance criterion of the security of the bundle: a user created outside of
 * the browser signs in on the form of the login page, the firewall opens the session of the core and
 * binds the browser to it, and an interaction begun in another HTTP session cannot be resumed, before
 * or after a login. The firewall is the one of tests/symfony/config/config_test.yml, declared as an
 * application declares it.
 */
final class LoginTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * OIDC Core §2 (auth_time, amr), RFC 8176 §2, architecture §3.2 and §3.5: what the login of the
     * firewall leaves behind, and how the interaction goes on with it.
     */
    #[Test]
    public function aUserCreatedOutsideOfTheBrowserSignsInAndTheInteractionGoesOn(): void
    {
        $user = self::userWithPassword('alice', self::PASSWORD);
        $before = new DateTimeImmutable();

        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));

        // the session of the core: who, since when, how, from where
        $session = $this->boundSession();
        static::assertTrue($session->user->id->equals($user->id));
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertGreaterThanOrEqual($before->setTime((int) $before->format('H'), (int) $before->format('i'), (int) $before->format('s')), $session->authenticatedAt());
        static::assertLessThanOrEqual(new DateTimeImmutable('+5 seconds'), $session->authenticatedAt());
        static::assertSame('127.0.0.1', $session->createdFrom->ipAddress);
        static::assertSame('Symfony BrowserKit', $session->createdFrom->userAgent);
        static::assertTrue($session->isActive(new DateTimeImmutable()));
        static::assertNull($session->authenticationContextClass);

        // the token of the firewall calls recent what the session calls auth_time (symfony/symfony#66014)
        static::assertSame($session->authenticatedAt()->getTimestamp(), $this->securityToken()->getAttribute(AuthenticatedVoter::AUTH_TIME_ATTRIBUTE));

        // the credential was used, the core was told
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($session->user) ?? static::fail('The credential is gone.');
        static::assertNotNull($credential->lastUsedAt);
        $events = self::events(UserAuthenticated::class);
        static::assertCount(1, $events);
        static::assertTrue($events[0]->session->id->equals($session->id));
        static::assertSame([], self::events(PasswordRehashed::class), 'A hash the policy produces is not rehashed.');

        // the interaction the browser began goes on with the session: consent is next
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §4.3: an interaction is resumed by the browser that began it and by no other, whether
     * the other is signed in or not.
     */
    #[Test]
    public function anInteractionBegunInAnotherHttpSessionCannotBeResumed(): void
    {
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $crawler = $this->loginPage($interaction);
        $token = $crawler->filter('input[name="_csrf_token"]')
            ->attr('value');
        static::assertIsString($token);

        // another browser: no cookie of the first one
        $this->browser->getCookieJar()
            ->clear();

        // the login page of that interaction is not for this browser
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());

        // nor is its form, whatever it posts: the firewall refuses a form token it did not give this
        // browser and opens no session
        $this->browser->request('POST', '/login?interaction=' . $interaction, [
            '_username' => 'alice',
            '_password' => self::PASSWORD,
            '_csrf_token' => $token,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));

        // signed in on an interaction of its own, this browser still cannot touch the first one
        $own = $this->authorize();
        $this->submitLogin($own, 'alice', self::PASSWORD);
        static::assertCount(1, self::sessionsOf('alice'));
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::service('test.heidi.interactions', InteractionRepositoryInterface::class)->find($interaction)?->isCompleted(), 'The first interaction is still pending.');
    }

    /**
     * Decision 0006 and architecture §3.4: the user gets one message whatever the reason, the audit
     * trail gets the reason.
     */
    #[Test]
    public function aWrongPasswordShowsTheFormAgainWithOneMessageAndOpensNoSession(): void
    {
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        $this->submitLogin($interaction, 'alice', 'not the password');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('alice', $failures[0]->identifier);
        static::assertTrue($failures[0]->user?->id->equals($user->id));
        static::assertSame('127.0.0.1', $failures[0]->context->ipAddress);

        // the page shows the form again, the username kept, one message; the message is shown once
        $crawler = $this->loginPage($interaction);
        static::assertSame('authentication_failed', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('alice', $crawler->filter('input[name="_username"]')->attr('value'));
        $crawler = $this->loginPage($interaction);
        static::assertCount(0, $crawler->filter('p[data-error]'));
    }

    /**
     * Decision 0006: an unknown user, a disabled user and a user without a password are refused exactly
     * like a wrong password; only the audit trail tells them apart.
     */
    #[Test]
    public function anUnknownADisabledOrAPasswordlessUserIsRefusedLikeAWrongPassword(): void
    {
        $disabled = self::userWithPassword('bob', self::PASSWORD);
        $disabled->disable(self::now());
        self::service('test.heidi.users', UserRepositoryInterface::class)
            ->save($disabled);
        $passwordless = self::user('carol', 'carol-subject');
        $interaction = $this->authorize();

        foreach ([
            'nobody' => [AuthenticationFailureReason::UnknownUser, null],
            'bob' => [AuthenticationFailureReason::DisabledUser, $disabled],
            'carol' => [AuthenticationFailureReason::NoSuchCredential, $passwordless],
        ] as $username => [$reason, $user]) {
            $this->submitLogin($interaction, $username, self::PASSWORD);
            $response = $this->browser->getResponse();
            static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), $username);
            static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'), $username);
            static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY), $username);
            $failures = self::events(AuthenticationFailed::class);
            static::assertCount(1, $failures, $username);
            static::assertSame($reason, $failures[0]->reason, $username);
            static::assertSame($username, $failures[0]->identifier, $username);
            if ($user === null) {
                static::assertNull($failures[0]->user, $username);
            } else {
                static::assertTrue($failures[0]->user?->id->equals($user->id), $username);
            }
            $crawler = $this->loginPage($interaction);
            static::assertSame('authentication_failed', $crawler->filter('p[data-error]')->attr('data-error'), $username);
        }
        static::assertSame([], self::sessionsOf('bob'));
        static::assertSame([], self::sessionsOf('carol'));
    }

    /**
     * A form posted without the token of this browser is not an attempt on an account: refused, nothing
     * opened, nothing recorded.
     */
    #[Test]
    public function aFormWithoutItsTokenIsRefusedAndNothingIsRecorded(): void
    {
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->loginPage($interaction);

        $this->browser->request('POST', '/login?interaction=' . $interaction, [
            '_username' => 'alice',
            '_password' => self::PASSWORD,
            '_csrf_token' => 'not-the-token',
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertSame([], self::events(UserAuthenticated::class));
        static::assertSame('authentication_failed', $this->loginPage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Architecture §3.4: a hash weaker than the policy of the core is replaced on the login that verified
     * it, and the core is told; the password itself did not change.
     */
    #[Test]
    public function aHashWeakerThanThePolicyIsRehashedOnLogin(): void
    {
        $user = self::userWithPassword('alice', self::PASSWORD, PasswordAlgorithm::Bcrypt);
        $interaction = $this->authorize();

        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        static::assertCount(1, self::sessionsOf('alice'));
        $managed = self::service('test.heidi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($managed) ?? static::fail('The credential is gone.');
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertNotNull($credential->lastUsedAt);
        $rehashes = self::events(PasswordRehashed::class);
        static::assertCount(1, $rehashes);
        static::assertTrue($rehashes[0]->credential->id->equals($credential->id));
        static::assertSame('127.0.0.1', $rehashes[0]->context->ipAddress);

        // the new hash opens the session next time too
        $this->browser->getCookieJar()
            ->clear();
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        static::assertCount(2, self::sessionsOf('alice'));
        static::assertSame([], self::events(PasswordRehashed::class));
    }

    /**
     * OIDC Core §3.1.2.1 (prompt=login) and architecture §3.2: a fresh login asked by a client records a
     * proof on the session the browser has, it does not open a second one.
     */
    #[Test]
    public function aFreshLoginAskedByTheClientRecordsAProofOnTheExistingSession(): void
    {
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $first = $this->boundSession();
        $firstAuthenticatedAt = $first->authenticatedAt();

        // the rows keep seconds: a request of the next second is what tells a login from a request
        sleep(1);
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        $crawler = $this->loginPage($interaction);
        static::assertSame('reauthentication_requested', $crawler->filter('p[data-requirement]')->attr('data-requirement'));
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        $sessions = self::sessionsOf('alice');
        static::assertCount(1, $sessions);
        $session = $this->boundSession();
        static::assertTrue($session->id->equals($first->id));
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertGreaterThanOrEqual($firstAuthenticatedAt, $session->authenticatedAt());
        static::assertSame($session->authenticatedAt()->getTimestamp(), $this->securityToken()->getAttribute(AuthenticatedVoter::AUTH_TIME_ATTRIBUTE));
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');

        // the interaction goes on: the login is fresh
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §3.2: two users do not share a cookie. Someone else signing in on a bound browser ends
     * the session of the first user and opens their own.
     */
    #[Test]
    public function anotherUserSigningInOnABoundBrowserEndsTheSessionOfTheFirst(): void
    {
        self::userWithPassword('alice', self::PASSWORD);
        self::userWithPassword('bob', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $alice = $this->boundSession();

        sleep(1);
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        $bob = $this->boundSession();
        static::assertTrue($bob->user->id->equals(self::sessionsOf('bob')[0]->user->id));
        static::assertFalse($bob->id->equals($alice->id));
        $ended = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->find($alice->id) ?? static::fail('The session of alice is gone.');
        static::assertTrue($ended->hasEnded());
        static::assertSame(SessionEnd::User, $ended->endedBy);
        $endings = self::events(AuthenticationSessionEnded::class);
        static::assertCount(1, $endings);
        static::assertTrue($endings[0]->session->id->equals($alice->id));
        static::assertCount(1, self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §5.2: the protocol plane sits outside of the firewall, no cookie is read there and no
     * session started, whatever the request.
     */
    #[Test]
    public function theProtocolPlaneStartsNoSession(): void
    {
        foreach ([
            ['GET', '/.well-known/openid-configuration'],
            ['GET', '/jwks'],
            ['POST', '/token'],
            ['GET', '/userinfo'],
        ] as [$method, $path]) {
            $this->browser->request($method, $path);
            static::assertFalse($this->browser->getResponse()->headers->has('Set-Cookie'), sprintf('%s %s set a cookie.', $method, $path));
        }
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return string the identifier of the interaction the browser was sent to the login page with
     */
    private function authorize(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters(parameters: $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));

        return $interaction;
    }

    private function loginPage(string $interaction): Crawler
    {
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * Fills and posts the form of the login page, as a user does.
     */
    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)
            ->selectButton('Sign in')
            ->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    /**
     * The session of the core the browser is bound to, read from the rows.
     */
    private function boundSession(): AuthenticationSession
    {
        $id = $this->readHttpSession()
            ->get(BrowserSession::AUTHENTICATION_SESSION_KEY);
        static::assertIsString($id, 'The browser is bound to no session.');
        self::reload();

        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->find(Uuid::fromString($id)) ?? static::fail('The bound session is gone.');
    }

    /**
     * The token the firewall stored in the HTTP session of the browser.
     */
    private function securityToken(): TokenInterface
    {
        $serialized = $this->readHttpSession()
            ->get('_security_heidi_interaction');
        static::assertIsString($serialized, 'The firewall stored no token.');
        $token = unserialize($serialized);
        static::assertInstanceOf(TokenInterface::class, $token);

        return $token;
    }

    /**
     * The active sessions of a user, from the rows.
     *
     * @return list<AuthenticationSession>
     */
    private static function sessionsOf(string $username): array
    {
        self::reload();
        $user = self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), $username);
        if (! $user instanceof User) {
            return [];
        }

        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->findActiveByUser($user, new DateTimeImmutable());
    }

    /**
     * The events of a class that reached the event bus during the last request.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    private static function events(string $class): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
