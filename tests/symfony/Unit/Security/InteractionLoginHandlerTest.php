<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Bundle\Http\InteractionPages;
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

    protected function setUp(): void
    {
        $routes = new RouteCollection();
        $routes->add('heidi_interaction_login', new Route('/login'));
        $router = new Router(new ClosureLoader(), static fn (): RouteCollection => $routes, [], new RequestContext());
        $this->handler = new InteractionLoginHandler(new InteractionPages(new Environment(new ArrayLoader())), $router);
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
        $request = Request::create('/login', 'POST', [
            'interaction' => 'from-the-body',
            '_target_path' => '/elsewhere',
        ], server: [
            'HTTP_REFERER' => 'https://op.test/login?interaction=from-the-referer',
        ]);

        // When
        $response = $this->handler->onAuthenticationSuccess($request, new NullToken());

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
