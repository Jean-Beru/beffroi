<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Controller;

use App\Controller\PasskeyLoginController;
use App\Http\InteractionPages;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Loader\ClosureLoader;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Router;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

/**
 * Architecture §5.4: the check path of the passkey login, reached only when no firewall took the POST,
 * sends the browser back to the login page and verifies nothing.
 */
final class PasskeyLoginControllerTest extends TestCase
{
    private PasskeyLoginController $controller;

    protected function setUp(): void
    {
        $routes = new RouteCollection();
        $routes->add('beffroi_interaction_login', new Route('/login'));
        $router = new Router(new ClosureLoader(), static fn (): RouteCollection => $routes, [], new RequestContext());
        $this->controller = new PasskeyLoginController(new InteractionPages(new Environment(new ArrayLoader()), $router));
    }

    #[Test]
    #[DataProvider('provideRequests')]
    public function aPostGoesBackToTheLoginPage(string $uri, string $location): void
    {
        // Given
        $request = Request::create($uri, 'POST', [
            '_passkey' => '{}',
        ]);

        // When
        $response = ($this->controller)($request);

        // Then
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame($location, $response->headers->get('Location'));
        static::assertSame('DENY', $response->headers->get('X-Frame-Options'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRequests(): iterable
    {
        yield 'with an interaction' => ['/login/passkey?interaction=abc', '/login?interaction=abc'];
        yield 'without' => ['/login/passkey', '/login'];
    }
}
