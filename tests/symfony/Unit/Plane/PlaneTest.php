<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Plane;

use App\Plane\Plane;
use App\Plane\PlaneRequestListener;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Bundle\SecurityBundle\EventListener\FirewallListener;
use Symfony\Component\HttpKernel\EventListener\RouterListener;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Architecture §5.2
 */
final class PlaneTest extends TestCase
{
    /**
     * @return iterable<string, array{Plane, string, bool}>
     */
    public static function provideRoutes(): iterable
    {
        yield 'provider serves the login' => [Plane::Provider, 'beffroi_interaction_login', true];
        yield 'provider serves the token endpoint' => [Plane::Provider, 'beffroi_protocol_token', true];
        yield 'provider refuses the administration API' => [Plane::Provider, 'beffroi_administration_tenant', false];
        yield 'provider serves the host' => [Plane::Provider, 'app_home', true];
        yield 'interaction serves the login' => [Plane::Interaction, 'beffroi_interaction_login', true];
        yield 'interaction refuses the token endpoint' => [Plane::Interaction, 'beffroi_protocol_token', false];
        yield 'interaction serves the host' => [Plane::Interaction, 'app_home', true];
        yield 'protocol refuses the login' => [Plane::Protocol, 'beffroi_interaction_login', false];
        yield 'protocol serves the token endpoint' => [Plane::Protocol, 'beffroi_protocol_token', true];
        yield 'protocol serves the host' => [Plane::Protocol, 'app_home', true];
        yield 'a prefix is not a plane' => [Plane::Protocol, 'beffroi_interaction', true];
    }

    #[Test]
    #[DataProvider('provideRoutes')]
    public function aPlaneServesItsRoutesAndThoseOfTheHost(Plane $plane, string $route, bool $served): void
    {
        // When / Then
        static::assertSame($served, $plane->serves($route));
    }

    /**
     * @return iterable<string, array{string, ?Plane}>
     */
    public static function provideRoutesAndTheirPlane(): iterable
    {
        yield 'the login is of the interaction plane' => ['beffroi_interaction_login', Plane::Interaction];
        yield 'the token endpoint is of the protocol plane' => ['beffroi_protocol_token', Plane::Protocol];
        yield 'a route of the application is of neither' => ['app_home', null];
        yield 'an endpoint of the FIDO conformance tools is of neither' => ['beffroi_fido_conformance_attestation_options', null];
        yield 'the automated approval of the conformance suite is of neither' => ['beffroi_ciba_conformance_approval', null];
        yield 'a prefix alone is of neither' => ['beffroi_interaction', null];
        yield 'no route is of neither' => ['', null];
    }

    /**
     * Architecture §5.2, Decision 0014
     */
    #[Test]
    #[DataProvider('provideRoutesAndTheirPlane')]
    public function theNameOfARouteCarriesItsPlane(string $route, ?Plane $plane): void
    {
        // When / Then
        static::assertSame($plane, Plane::ofRoute($route));
    }

    #[Test]
    #[DataProvider('provideRoutesTheProtocolPlaneServes')]
    public function theListenerLetsTheRoutesOfItsPlaneAndOfTheHostThrough(?string $route): void
    {
        // Given
        $listener = new PlaneRequestListener(Plane::Protocol);
        $event = self::event($route);

        // When
        $listener($event);

        // Then
        static::assertNull($event->getResponse());
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideRoutesTheProtocolPlaneServes(): iterable
    {
        yield 'a route of the plane' => ['beffroi_protocol_jwks'];
        yield 'a route of the host' => ['app_home'];
        yield 'the profiler of the host, in development' => ['_profiler'];
        yield 'the web debug toolbar of the host, in development' => ['_wdt'];
        yield 'no route' => [null];
    }

    #[Test]
    public function theListenerRefusesARouteOfTheOtherPlaneWithANotFound(): void
    {
        // Given
        $listener = new PlaneRequestListener(Plane::Protocol);
        $event = self::event('beffroi_interaction_login');

        // When
        try {
            $listener($event);
            static::fail('The route of the other plane is refused.');
        } catch (NotFoundHttpException $exception) {
            // Then
            static::assertSame(404, $exception->getStatusCode());
            static::assertStringContainsString('beffroi_interaction_login', $exception->getMessage());
            static::assertStringContainsString('BEFFROI_PLANE=protocol', $exception->getMessage());
        }
    }

    #[Test]
    public function theListenerRunsAfterTheRouterAndBeforeTheFirewall(): void
    {
        // Given
        $router = RouterListener::getSubscribedEvents()[KernelEvents::REQUEST][0][1] ?? null;
        $firewall = FirewallListener::getSubscribedEvents()[KernelEvents::REQUEST][1][1] ?? null;

        // When / Then
        static::assertLessThan($router, PlaneRequestListener::PRIORITY);
        static::assertGreaterThan($firewall, PlaneRequestListener::PRIORITY);
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
