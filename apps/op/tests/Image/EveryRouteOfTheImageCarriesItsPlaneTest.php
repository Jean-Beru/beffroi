<?php

declare(strict_types=1);

namespace App\Tests\Image;

use App\Kernel;
use App\Plane\Plane;
use function array_keys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\RouterInterface;

/**
 * Issue #988, decision 0019: every route the image serves carries its plane in its name, which is what
 * BEFFROI_PLANE reads (Plane::ofRoute). A route of the image without one would be served by a process of
 * either plane, a form meant for a browser by a process that serves the protocol alone among them.
 *
 * The routes are those of the kernel of production, the one the image compiles. The routes of development
 * and of the suite of this application, the endpoints of the conformance tools and the pages of the
 * demonstration, are imported in those environments only and carry no plane.
 */
final class EveryRouteOfTheImageCarriesItsPlaneTest extends TestCase
{
    #[Test]
    #[DataProvider('provideTheRoutesOfProduction')]
    public function aRouteOfProductionCarriesItsPlane(string $name): void
    {
        // When
        $plane = Plane::ofRoute($name);

        // Then
        static::assertNotNull($plane);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTheRoutesOfProduction(): iterable
    {
        $kernel = new Kernel('prod', false);
        $kernel->boot();
        try {
            $router = $kernel->getContainer()->get('router');
            static::assertInstanceOf(RouterInterface::class, $router);
            foreach (array_keys($router->getRouteCollection()->all()) as $name) {
                yield $name => [$name];
            }
        } finally {
            $kernel->shutdown();
        }
    }
}
