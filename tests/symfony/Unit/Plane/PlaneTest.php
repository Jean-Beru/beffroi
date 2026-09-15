<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Plane;

use Heidi\Bundle\Plane\Plane;
use Heidi\Bundle\Plane\PlaneRequestListener;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\EventListener\RouterListener;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Architecture §5.2: a plane serves its own routes, "all" serves everything, and a route that is not the
 * bundle's belongs to the host application.
 */
final class PlaneTest extends TestCase
{
    /**
     * @return iterable<string, array{Plane, string, bool}>
     */
    public static function routes(): iterable
    {
        yield 'all serves the login' => [Plane::All, 'heidi_interaction_login', true];
        yield 'all serves the token endpoint' => [Plane::All, 'heidi_protocol_token', true];
        yield 'all serves the host' => [Plane::All, 'app_home', true];
        yield 'interaction serves the login' => [Plane::Interaction, 'heidi_interaction_login', true];
        yield 'interaction refuses the token endpoint' => [Plane::Interaction, 'heidi_protocol_token', false];
        yield 'interaction serves the host' => [Plane::Interaction, 'app_home', true];
        yield 'protocol refuses the login' => [Plane::Protocol, 'heidi_interaction_login', false];
        yield 'protocol serves the token endpoint' => [Plane::Protocol, 'heidi_protocol_token', true];
        yield 'protocol serves the host' => [Plane::Protocol, 'app_home', true];
        yield 'a prefix is not a plane' => [Plane::Protocol, 'heidi_interaction', true];
    }

    #[Test]
    #[DataProvider('routes')]
    public function aPlaneServesItsRoutesAndThoseOfTheHost(Plane $plane, string $route, bool $served): void
    {
        static::assertSame($served, $plane->serves($route));
    }

    #[Test]
    public function theListenerRefusesARouteOfTheOtherPlaneWithANotFound(): void
    {
        $listener = new PlaneRequestListener(Plane::Protocol);

        $listener(self::event('heidi_protocol_jwks'));
        $listener(self::event('app_home'));
        $listener(self::event(null));

        try {
            $listener(self::event('heidi_interaction_login'));
            static::fail('The route of the other plane is refused.');
        } catch (NotFoundHttpException $exception) {
            static::assertSame(404, $exception->getStatusCode());
            static::assertStringContainsString('heidi_interaction_login', $exception->getMessage());
            static::assertStringContainsString('HEIDI_PLANE=protocol', $exception->getMessage());
        }
    }

    /**
     * The route name is what the RouterListener sets: the guard runs after it and before the firewall.
     */
    #[Test]
    public function theListenerRunsAfterTheRouterAndBeforeTheFirewall(): void
    {
        $routerPriority = RouterListener::getSubscribedEvents()[KernelEvents::REQUEST][0][1] ?? null;

        static::assertSame(32, $routerPriority);
        static::assertLessThan($routerPriority, PlaneRequestListener::PRIORITY);
        static::assertGreaterThan(8, PlaneRequestListener::PRIORITY);
    }

    private static function event(?string $route): RequestEvent
    {
        $request = Request::create('/');
        if ($route !== null) {
            $request->attributes->set('_route', $route);
        }

        return new RequestEvent(static::createStub(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
    }
}
