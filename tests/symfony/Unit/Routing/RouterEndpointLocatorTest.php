<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Routing;

use DateTimeImmutable;
use Heidi\Bundle\Routing\RouterEndpointLocator;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Exception\InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.8 and §5.2: the endpoints are the routes of the bundle under the origin of the
 * issuer; the host of the request plays no part; the discovery document must sit where OIDC Discovery
 * §4.1 makes clients look for it.
 */
final class RouterEndpointLocatorTest extends TestCase
{
    #[Test]
    public function theEndpointsAreTheRoutesUnderTheOriginOfTheIssuer(): void
    {
        $locator = new RouterEndpointLocator(self::router(''));

        $endpoints = $locator->locate(self::tenant('https://op.example'));

        static::assertSame('https://op.example/authorize', $endpoints->authorization);
        static::assertSame('https://op.example/token', $endpoints->token);
        static::assertSame('https://op.example/userinfo', $endpoints->userinfo);
        static::assertSame('https://op.example/jwks', $endpoints->jwks);
        static::assertSame('https://op.example/logout', $endpoints->endSession);
    }

    /**
     * The request came in on another host, or on a port the issuer does not name: the issuer wins.
     */
    #[Test]
    public function theHostOfTheRequestIsIgnored(): void
    {
        $locator = new RouterEndpointLocator(self::router('', new RequestContext('', 'GET', 'attacker.example', 'http', 8080)));

        $endpoints = $locator->locate(self::tenant('https://op.example:8443'));

        static::assertSame('https://op.example:8443/token', $endpoints->token);
    }

    /**
     * An issuer with a path, the routes mounted under it (OIDC Discovery §4.1).
     */
    #[Test]
    public function anIssuerWithAPathHasItsRoutesUnderThatPath(): void
    {
        $locator = new RouterEndpointLocator(self::router('/tenant1'));

        $endpoints = $locator->locate(self::tenant('https://op.example/tenant1'));

        static::assertSame('https://op.example/tenant1/authorize', $endpoints->authorization);
        static::assertSame('https://op.example/tenant1/token', $endpoints->token);
    }

    /**
     * The routes are not under the path of the issuer: clients would look for the discovery document
     * where nothing is served. A configuration fault, refused rather than announced.
     */
    #[Test]
    public function routesMountedElsewhereThanTheIssuerAreRefused(): void
    {
        $locator = new RouterEndpointLocator(self::router('/auth'));

        try {
            $locator->locate(self::tenant('https://op.example'));
            static::fail('The routes are not under the issuer.');
        } catch (LogicException $exception) {
            static::assertStringContainsString('https://op.example/.well-known/openid-configuration', $exception->getMessage());
            static::assertStringContainsString('https://op.example/auth/.well-known/openid-configuration', $exception->getMessage());
        }
    }

    /**
     * RFC 6749 §3.2: the token endpoint must be HTTPS, and the issuer says so; a loopback issuer in
     * clear (allowed for development) cannot announce one.
     */
    #[Test]
    public function aLoopbackIssuerInClearCannotAnnounceATokenEndpoint(): void
    {
        $locator = new RouterEndpointLocator(self::router(''));

        $this->expectException(InvalidArgumentException::class);
        $locator->locate(self::tenant('http://localhost:8000'));
    }

    private static function router(string $prefix, ?RequestContext $context = null): UrlGenerator
    {
        $routes = new RouteCollection();
        $routes->add('heidi_protocol_discovery', new Route($prefix . '/.well-known/openid-configuration'));
        $routes->add('heidi_protocol_jwks', new Route($prefix . '/jwks'));
        $routes->add('heidi_protocol_token', new Route($prefix . '/token'));
        $routes->add('heidi_protocol_userinfo', new Route($prefix . '/userinfo'));
        $routes->add('heidi_interaction_authorize', new Route($prefix . '/authorize'));
        $routes->add('heidi_interaction_logout', new Route($prefix . '/logout'));

        return new UrlGenerator($routes, $context ?? new RequestContext());
    }

    private static function tenant(string $issuer): Tenant
    {
        return new Tenant(Uuid::v7(), 'default', new Issuer($issuer), 'Test', new DateTimeImmutable('2026-09-15T10:00:00+00:00'));
    }
}
