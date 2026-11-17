<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use App\Plane\Plane;
use function array_fill_keys;
use function array_keys;
use function preg_match_all;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use function strtr;
use Symfony\Component\Routing\RouterInterface;

/**
 * Decision 0038: the walk of every route of the administration API, and of a path none of them serves, with a request
 * that is not an administrator's. Each one is refused as its token is, a 401, before anything is read and whatever the
 * path names, so a route added without the guard fails here. A token of a session that does not satisfy
 * phishing_resistant is not among them: the provider mints none for the API (AdministrationAudience), so the refusal
 * of one is played where such a token can be made, AdministratorOfARequestTest.
 */
final class AdministrationApiGuardTest extends AdministrationTestCase
{
    /**
     * What stands in the path of a route for each of its parameters.
     */
    private const array PARAMETERS = [
        '{clientId}' => self::CLIENT,
        '{id}' => '0193b8d0-0000-7000-8000-000000000000',
        '{session}' => '0193b8d0-0000-7000-8000-000000000001',
        '{credential}' => '0193b8d0-0000-7000-8000-000000000002',
        '{person}' => '0193b8d0-0000-7000-8000-000000000003',
        '{consent}' => '0193b8d0-0000-7000-8000-000000000004',
        '{path}' => 'nothing/here',
    ];

    #[Test]
    public function noRouteAnswersARequestWithoutAToken(): void
    {
        // Given
        $paths = $this->pathsOfTheApi();

        // When
        $statuses = $this->statusesOf($paths, null, true);

        // Then
        static::assertSame(array_fill_keys(array_keys($paths), 401), $statuses);
    }

    #[Test]
    public function noRouteAnswersAPersonTakenOutOfTheGroupSinceTheirTokenWasIssued(): void
    {
        // Given
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        self::leavesTheirGroups($alice);
        $paths = $this->pathsOfTheApi();

        // When
        $statuses = $this->statusesOf($paths, $token, true);

        // Then
        static::assertSame(array_fill_keys(array_keys($paths), 401), $statuses);
    }

    #[Test]
    public function noRouteAnswersATokenPresentedWithoutTheProofOfItsKey(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $paths = $this->pathsOfTheApi();

        // When
        $statuses = $this->statusesOf($paths, $token, false);

        // Then
        static::assertSame(array_fill_keys(array_keys($paths), 401), $statuses);
    }

    #[Test]
    public function noRouteAnswersATokenAddressedToAnotherAudience(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'), null);
        $paths = $this->pathsOfTheApi();

        // When
        $statuses = $this->statusesOf($paths, $token, true);

        // Then
        static::assertSame(array_fill_keys(array_keys($paths), 401), $statuses);
    }

    /**
     * The kernel that serves the endpoints and the pages does not load the routes of the API: a deployment that runs no
     * process of its plane has no such API, rather than having it and refusing it.
     */
    #[Test]
    public function theProviderLoadsNoRouteOfTheApi(): void
    {
        // When
        $router = self::getContainer()->get('router');

        // Then
        static::assertInstanceOf(RouterInterface::class, $router);
        $names = [];
        foreach (array_keys($router->getRouteCollection()->all()) as $name) {
            if (str_starts_with($name, Plane::ADMINISTRATION_ROUTE_PREFIX)) {
                $names[] = $name;
            }
        }
        static::assertSame([], $names);
    }

    /**
     * A process of the plane of the administration loads its routes and no other.
     */
    #[Test]
    public function theApiLoadsItsRoutesAlone(): void
    {
        // When
        $names = array_keys($this->routesOfTheApi());

        // Then
        $others = [];
        foreach ($names as $name) {
            if (! str_starts_with($name, Plane::ADMINISTRATION_ROUTE_PREFIX)) {
                $others[] = $name;
            }
        }
        static::assertSame([], $others);
    }

    /**
     * Every route of the API, by name, as the method and the path a request can name.
     *
     * @return array<string, array{string, string}>
     */
    private function pathsOfTheApi(): array
    {
        $paths = [];
        foreach ($this->routesOfTheApi() as $name => [$method, $path]) {
            $paths[$name] = [$method, strtr($path, self::PARAMETERS)];
            if (preg_match_all('/\{[^}]+\}/', $paths[$name][1]) !== 0) {
                static::fail(sprintf('The route "%s" has a parameter this walk does not know how to fill: %s.', $name, $path));
            }
        }

        return $paths;
    }

    /**
     * @param array<string, array{string, string}> $paths
     *
     * @return array<string, int>
     */
    private function statusesOf(array $paths, ?string $token, bool $proven): array
    {
        $statuses = [];
        foreach ($paths as $name => [$method, $path]) {
            $statuses[$name] = $this->api($path, $token, $proven, method: $method)->getStatusCode();
        }

        return $statuses;
    }
}
