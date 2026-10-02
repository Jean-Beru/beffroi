<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Load;

use DateInterval;
use Beffroi\Bundle\Load\LoadBudget;
use Beffroi\Bundle\Load\OriginLoadListener;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\SecurityBundle\EventListener\FirewallListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\EventListener\RouterListener;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * Decision 0014: the budget of an origin is consumed on the routes of the two planes and on nothing
 * else, keyed by the address of the caller, once the route is named and before the firewall.
 */
final class OriginLoadListenerTest extends TestCase
{
    /**
     * One request, so that the second shows whether the first was counted.
     */
    private const int BUDGET = 1;

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideRoutesThatAreNotTheBundleS(): iterable
    {
        yield 'a route of the host application' => ['app_home'];
        yield 'the profiler, in development' => ['_profiler'];
        yield 'an endpoint of the FIDO conformance tools, in development' => ['beffroi_fido_conformance_attestation_options'];
        yield 'no route at all' => [null];
    }

    #[Test]
    #[DataProvider('provideRoutesThatAreNotTheBundleS')]
    public function aRouteThatIsNotOfTheTwoPlanesIsNotCounted(?string $route): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event($route));

        // When
        $listener(self::event($route));

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aRouteOfAPlaneIsCounted(): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event('beffroi_protocol_token'));

        // Then
        $this->expectException(LoadBudgetSpentException::class);

        // When
        $listener(self::event('beffroi_protocol_token'));
    }

    /**
     * A sub-request is the request being served, not another one the provider received.
     */
    #[Test]
    public function aSubRequestIsNotCountedAgain(): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event('beffroi_protocol_token', HttpKernelInterface::SUB_REQUEST));

        // When
        $listener(self::event('beffroi_protocol_token', HttpKernelInterface::SUB_REQUEST));

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * Decision 0014: the key is the address of the caller, so what one address spends leaves the window
     * of another untouched.
     */
    #[Test]
    public function theKeyIsTheAddressOfTheCaller(): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event('beffroi_protocol_token', address: '198.51.100.7'));

        // When
        $listener(self::event('beffroi_protocol_token', address: '198.51.100.8'));

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * The route name is what the RouterListener sets, and nothing of the firewall has run yet: the
     * budget is consumed before a session is opened or a hash paid.
     */
    #[Test]
    public function theListenerRunsAfterTheRouterAndBeforeTheFirewall(): void
    {
        // Given
        $router = RouterListener::getSubscribedEvents()[KernelEvents::REQUEST][0][1] ?? null;
        $firewall = FirewallListener::getSubscribedEvents()[KernelEvents::REQUEST][1][1] ?? null;

        // When / Then
        static::assertSame(32, $router);
        static::assertSame(8, $firewall);
        static::assertLessThan($router, OriginLoadListener::PRIORITY);
        static::assertGreaterThan($firewall, OriginLoadListener::PRIORITY);
    }

    private static function listener(): OriginLoadListener
    {
        return new OriginLoadListener(new LoadBudget(LoadBudget::ORIGIN, self::BUDGET, new DateInterval('PT60S'), new InMemoryStorage()));
    }

    private static function event(?string $route, int $type = HttpKernelInterface::MAIN_REQUEST, string $address = '198.51.100.7'): RequestEvent
    {
        $request = Request::create('/', server: [
            'REMOTE_ADDR' => $address,
        ]);
        if ($route !== null) {
            $request->attributes->set('_route', $route);
        }

        return new RequestEvent(static::createStub(HttpKernelInterface::class), $request, $type);
    }
}
