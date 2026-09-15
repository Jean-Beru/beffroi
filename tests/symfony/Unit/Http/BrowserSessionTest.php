<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use Heidi\Bundle\Http\BrowserSession;
use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Architecture §3.2 and §4.3: the cookie side of a session of the core, and the interactions a browser
 * may resume.
 */
final class BrowserSessionTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryInteractionRepository $interactions;

    private BrowserSession $browser;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->interactions = new InMemoryInteractionRepository();
        $this->browser = new BrowserSession($this->sessions, $this->interactions, new MockClock(Fixtures::now()->modify('+1 minute')));
    }

    #[Test]
    public function aRequestWithoutASessionCookieIsNotAuthenticated(): void
    {
        $request = Request::create('/authorize');
        $request->setSession(new Session(new MockArraySessionStorage()));

        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
        static::assertFalse($request->getSession()->isStarted(), 'A request without a cookie starts no session.');
    }

    #[Test]
    public function aBoundBrowserIsAuthenticated(): void
    {
        $session = $this->session();
        $request = self::request();
        $this->browser->bind($request->getSession(), $session);

        static::assertSame($session, $this->browser->authenticationSession($request, $this->tenant));
    }

    /**
     * An identifier fixed before the login opens nothing after it.
     */
    #[Test]
    public function bindingRegeneratesTheHttpSessionIdentifier(): void
    {
        $request = self::request();
        $before = $request->getSession()
            ->getId();

        $this->browser->bind($request->getSession(), $this->session());

        static::assertNotSame($before, $request->getSession()->getId());
    }

    #[Test]
    public function anEndedSessionIsForgotten(): void
    {
        $session = $this->session();
        $request = self::request();
        $this->browser->bind($request->getSession(), $session);
        $session->end(SessionEnd::User, Fixtures::now());

        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
        static::assertFalse($request->getSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
    }

    #[Test]
    public function aSessionOfAnotherTenantIsNotThisBrowsers(): void
    {
        $request = self::request();
        $this->browser->bind($request->getSession(), $this->session());

        static::assertNull($this->browser->authenticationSession($request, Fixtures::tenant('other', 'https://other.example')));
    }

    #[Test]
    public function aBindingToNothingIsNotAuthenticated(): void
    {
        $request = self::request();
        $request->getSession()
            ->set(BrowserSession::AUTHENTICATION_SESSION_KEY, 'not-a-uuid');

        static::assertNull($this->browser->authenticationSession($request, $this->tenant));

        $request->getSession()
            ->set(BrowserSession::AUTHENTICATION_SESSION_KEY, '019968a0-0000-7000-8000-000000000000');

        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
    }

    #[Test]
    public function unbindingInvalidatesTheHttpSession(): void
    {
        $request = self::request();
        $this->browser->bind($request->getSession(), $this->session());
        $interaction = $this->interaction();
        $this->browser->begin($request->getSession(), $interaction);

        $this->browser->unbind($request->getSession());

        static::assertNull($this->browser->authenticationSession($request, $this->tenant));
        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));
    }

    #[Test]
    public function anInteractionIsPendingForTheBrowserThatBeganIt(): void
    {
        $interaction = $this->interaction();
        $request = self::request();

        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id), 'Not begun by this browser.');

        $this->browser->begin($request->getSession(), $interaction);

        static::assertSame($interaction, $this->browser->pending($request, $this->tenant, $interaction->id));
        static::assertNull($this->browser->pending($request, $this->tenant, null));
        static::assertNull($this->browser->pending($request, $this->tenant, ''));
        static::assertNull($this->browser->pending($request, $this->tenant, 'unknown'));
        static::assertNull($this->browser->pending($request, Fixtures::tenant('other', 'https://other.example'), $interaction->id));
    }

    #[Test]
    public function anInteractionThatIsOverIsNotPendingAnyMore(): void
    {
        $interaction = $this->interaction();
        $request = self::request();
        $this->browser->begin($request->getSession(), $interaction);

        $this->browser->forget($request->getSession(), $interaction);

        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));
        static::assertFalse($request->getSession()->has(BrowserSession::INTERACTIONS_KEY));
    }

    /**
     * One tab per interaction, the oldest forgotten first.
     */
    #[Test]
    public function aBrowserHoldsABoundedNumberOfInteractions(): void
    {
        $request = self::request();
        $first = $this->interaction();
        $second = $this->interaction();
        $this->browser->begin($request->getSession(), $first);
        $this->browser->begin($request->getSession(), $second);
        for ($i = 2; $i < BrowserSession::MAX_PENDING_INTERACTIONS; $i++) {
            $this->browser->begin($request->getSession(), $this->interaction());
        }
        $last = $this->interaction();
        $this->browser->begin($request->getSession(), $last);

        static::assertNull($this->browser->pending($request, $this->tenant, $first->id));
        static::assertSame($second, $this->browser->pending($request, $this->tenant, $second->id));
        static::assertSame($last, $this->browser->pending($request, $this->tenant, $last->id));
    }

    #[Test]
    public function aCorruptedListOfInteractionsIsAnEmptyOne(): void
    {
        $interaction = $this->interaction();
        $request = self::request();
        $request->getSession()
            ->set(BrowserSession::INTERACTIONS_KEY, 'not-a-list');

        static::assertNull($this->browser->pending($request, $this->tenant, $interaction->id));

        $request->getSession()
            ->set(BrowserSession::INTERACTIONS_KEY, [$interaction->id, 42]);

        static::assertSame($interaction, $this->browser->pending($request, $this->tenant, $interaction->id));
    }

    /**
     * A request that carries the cookie of the session.
     */
    private static function request(): Request
    {
        $request = Request::create('/authorize');
        $session = new Session(new MockArraySessionStorage());
        $request->setSession($session);
        $request->cookies->set($session->getName(), 'cookie');

        return $request;
    }

    private function session(): AuthenticationSession
    {
        $session = Fixtures::session(Fixtures::user($this->tenant), Fixtures::now());
        $this->sessions->save($session);

        return $session;
    }

    private function interaction(): Interaction
    {
        $request = Requests::authorization(Clients::public($this->tenant));
        $interaction = new Interaction(Interaction::generateId(), $this->tenant, $request, null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $this->interactions->save($interaction);

        return $interaction;
    }
}
