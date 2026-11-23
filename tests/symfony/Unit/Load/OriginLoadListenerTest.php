<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Load;

use DateInterval;
use App\Load\LoadBudget;
use App\Load\OriginLoadListener;
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
 * Decision 0014
 */
final class OriginLoadListenerTest extends TestCase
{
    private const int BUDGET = 1;

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideRoutesThatAreNotTheProviderS(): iterable
    {
        yield 'a route of the application' => ['app_home'];
        yield 'the profiler, in development' => ['_profiler'];
        yield 'an endpoint of the FIDO conformance tools, in development' => ['beffroi_fido_conformance_attestation_options'];
        yield 'no route at all' => [null];
    }

    #[Test]
    #[DataProvider('provideRoutesThatAreNotTheProviderS')]
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
     * Decision 0014
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
     * Decision 0014, RFC 4291 §2.5.1
     */
    #[Test]
    public function twoAddressesOfOneIpv6PrefixOfSixtyFourBitsShareTheBudget(): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event('beffroi_protocol_token', address: '2001:db8:1:2::1'));

        // Then
        $this->expectException(LoadBudgetSpentException::class);

        // When
        $listener(self::event('beffroi_protocol_token', address: '2001:db8:1:2:ffff:ffff:ffff:fffe'));
    }

    /**
     * Decision 0014, RFC 4291 §2.5.1
     */
    #[Test]
    public function twoIpv6PrefixesOfSixtyFourBitsHaveABudgetEach(): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event('beffroi_protocol_token', address: '2001:db8:1:2::1'));

        // When
        $listener(self::event('beffroi_protocol_token', address: '2001:db8:1:3::1'));

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function anIpv4AddressMappedIntoIpv6KeepsItsBudget(): void
    {
        // Given
        $listener = self::listener();
        $listener(self::event('beffroi_protocol_token', address: '::ffff:198.51.100.7'));

        // When
        $listener(self::event('beffroi_protocol_token', address: '::ffff:198.51.100.8'));

        // Then
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function theListenerRunsAfterTheRouterAndBeforeTheFirewall(): void
    {
        // Given
        $router = RouterListener::getSubscribedEvents()[KernelEvents::REQUEST][0][1] ?? null;
        $firewall = FirewallListener::getSubscribedEvents()[KernelEvents::REQUEST][1][1] ?? null;

        // When / Then
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
