<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\LoginTarget;
use Heidi\Bundle\Security\InteractionLoginHandler;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Loader\ClosureLoader;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Router;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

/**
 * Architecture §5.4: after the form login, the browser goes back to the login page of its interaction,
 * whether the login succeeded or failed.
 */
final class InteractionLoginHandlerTest extends TestCase
{
    private InteractionLoginHandler $handler;

    private LoginTarget $loginTargets;

    protected function setUp(): void
    {
        $routes = new RouteCollection();
        $routes->add('heidi_interaction_login', new Route('/login'));
        $routes->add('heidi_interaction_device', new Route('/device'));
        $router = new Router(new ClosureLoader(), static fn (): RouteCollection => $routes, [], new RequestContext());
        $pages = new InteractionPages(new Environment(new ArrayLoader()), $router);
        $this->loginTargets = new LoginTarget($pages);
        $this->handler = new InteractionLoginHandler($pages, $this->loginTargets);
    }

    #[Test]
    public function aSuccessGoesBackToTheLoginPageOfTheInteraction(): void
    {
        // Given
        $request = Request::create('/login?interaction=abc', 'POST');

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

        // Then
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=abc', $response->headers->get('Location'));
    }

    /**
     * Architecture §5.4: every response of the interaction plane carries the headers of the pages.
     */
    #[Test]
    public function theRedirectCarriesTheHeadersOfTheInteractionPages(): void
    {
        // Given
        $request = Request::create('/login?interaction=abc', 'POST');

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

        // Then
        static::assertSame('DENY', $response->headers->get('X-Frame-Options'));
        static::assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * The target is the query of the form action, never the body nor a referer.
     */
    #[Test]
    public function theInteractionIsReadFromTheQueryOnly(): void
    {
        // Given
        $request = Request::create(
            '/login',
            'POST',
            [
                'interaction' => 'from-the-body',
                '_target_path' => '/elsewhere',
            ],
            server: [
                'HTTP_REFERER' => 'https://op.test/login?interaction=from-the-referer',
            ],
        );

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

        // Then
        static::assertSame('/login', $response->headers->get('Location'));
    }

    /**
     * RFC 8628 §3.3: the page a user approves what an appliance asked is not an interaction, and the login
     * of the same firewall brings the browser back to it with the code it typed.
     */
    #[Test]
    public function aSuccessGoesBackToThePageThatAskedForTheLogin(): void
    {
        // Given
        $request = Request::create('/login', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $this->loginTargets->sendToLogin($request->getSession(), 'heidi_interaction_device', [
            'user_code' => 'BCDFGHJK',
        ]);

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

        // Then
        static::assertSame('/device?user_code=BCDFGHJK', $response->headers->get('Location'));
    }

    /**
     * The page that asked stays remembered until it is served: a password verified for a user who holds a
     * second factor is not a login yet (§5.4), and the page it was waiting for must still be there after the
     * code.
     */
    #[Test]
    public function thePageThatAskedStaysRememberedUntilItIsServed(): void
    {
        // Given
        $request = Request::create('/login', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $this->loginTargets->sendToLogin($request->getSession(), 'heidi_interaction_device');
        $this->handler->onAuthenticationSuccess($request, new NullToken());

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

        // Then
        static::assertSame('/device', $response->headers->get('Location'));
    }

    /**
     * An interaction named in the query of the form action is what that login was for: a page remembered from
     * an abandoned flow does not take a browser away from the client that sent it.
     */
    #[Test]
    public function anInteractionNamedByTheFormWinsOverThePageThatAsked(): void
    {
        // Given
        $request = Request::create('/login?interaction=abc', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $this->loginTargets->sendToLogin($request->getSession(), 'heidi_interaction_device');

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

        // Then
        static::assertSame('/login?interaction=abc', $response->headers->get('Location'));
    }

    /**
     * A refused login goes back to the login page and never to the page that asked for it: that page would
     * send the browser here again, and the message would be read by nobody.
     */
    #[Test]
    public function aRefusedLoginGoesBackToTheLoginPageAndNotToThePageThatAsked(): void
    {
        // Given
        $request = Request::create('/login', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $this->loginTargets->sendToLogin($request->getSession(), 'heidi_interaction_device');

        // When
        $response = $this->handler->onAuthenticationFailure($request, new BadCredentialsException('Bad credentials.'));

        // Then
        static::assertSame('/login', $response->headers->get('Location'));
    }

    #[Test]
    public function aFailureIsKeptForThePageAndGoesBackToIt(): void
    {
        // Given
        $request = Request::create('/login?interaction=abc', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $exception = new BadCredentialsException('Bad credentials.');

        // When
        $response = $this->handler->onAuthenticationFailure($request, $exception);

        // Then
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=abc', $response->headers->get('Location'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame($exception, $request->getSession()->get(SecurityRequestAttributes::AUTHENTICATION_ERROR));
    }
}
