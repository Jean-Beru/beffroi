<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Client;

use Beffroi\Bundle\Client\SelfClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Issue #282: the application that hosts the bundle names its routes, and what it registers is what the router writes
 * for them under the origin of the issuer, the application and the provider being served under the same host.
 */
final class SelfClientTest extends TestCase
{
    private const string SECRET = 'the-secret-of-the-application-of-at-least-32-characters';

    private const string KERNEL_SECRET = 'the-secret-of-the-kernel';

    /**
     * What a deployment would write for it under "clients" (architecture §5.1): the URL of each route, its secret, and
     * the consent a first-party application is the named exception of; everything else is left to the defaults.
     */
    #[Test]
    public function itDeclaresWhatADeploymentWouldWriteForItUnderClients(): void
    {
        // Given
        $client = new SelfClient(self::router(), 'https://op.example', 'app_oidc_callback', 'app_home', self::SECRET, self::KERNEL_SECRET);

        // When
        $declaration = $client->declaration();

        // Then
        static::assertSame(
            [
                'secret' => self::SECRET,
                'redirect_uris' => ['https://op.example/oidc/callback'],
                'post_logout_redirect_uris' => ['https://op.example/'],
                'requires_consent' => false,
            ],
            $declaration,
        );
    }

    /**
     * An issuer with a path mounts the routes of the bundle under it (OIDC Discovery §4.1), not the routes of the
     * application: the URL of a route of the application is its path under the origin, never under the issuer.
     */
    #[Test]
    public function aRouteOfTheApplicationIsUnderTheOriginOfAnIssuerWithAPath(): void
    {
        // Given
        $client = new SelfClient(self::router(), 'https://op.example/idp', 'app_oidc_callback', null, self::SECRET, self::KERNEL_SECRET);

        // When
        $declaration = $client->declaration();

        // Then
        static::assertSame(['https://op.example/oidc/callback'], $declaration['redirect_uris']);
    }

    /**
     * The request being served came in on another host, or on a port the issuer does not name: the issuer wins, as it
     * does for the endpoints of the provider (architecture §4.8).
     */
    #[Test]
    public function theHostOfTheRequestPlaysNoPart(): void
    {
        // Given
        $client = new SelfClient(
            self::router(new RequestContext('', 'GET', 'attacker.example', 'http', 8080)),
            'https://op.example:8443',
            'app_oidc_callback',
            null,
            self::SECRET,
            self::KERNEL_SECRET,
        );

        // When
        $declaration = $client->declaration();

        // Then
        static::assertSame(['https://op.example:8443/oidc/callback'], $declaration['redirect_uris']);
    }

    /**
     * RP-Initiated Logout §3: an application that names no route to come back to after a logout registers none, and a
     * logout request that names one is then refused like any other.
     */
    #[Test]
    public function anApplicationThatNamesNoRouteAfterALogoutRegistersNone(): void
    {
        // Given
        $client = new SelfClient(self::router(), 'https://op.example', 'app_oidc_callback', null, self::SECRET, self::KERNEL_SECRET);

        // When
        $declaration = $client->declaration();

        // Then
        static::assertSame([], $declaration['post_logout_redirect_uris']);
    }

    /**
     * The secret of the kernel signs and seals what the application holds, and a token request carries the secret of
     * the client over HTTP: the application authenticates with a secret of its own, whatever variable carries it.
     */
    #[Test]
    public function theSecretOfTheKernelIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "self_client.secret" is the secret of the kernel: the application authenticates with a secret of its own, which its token requests carry over HTTP.');

        // When
        new SelfClient(self::router(), 'https://op.example', 'app_oidc_callback', null, self::SECRET, self::SECRET);
    }

    /**
     * A route the router cannot write a URL for is refused by the key that named it, when the client is built rather
     * than at the first request it would have answered wrong.
     */
    #[Test]
    #[DataProvider('provideRoutesTheRouterWritesNoUrlFor')]
    public function aRouteTheRouterWritesNoUrlForIsRefused(string $redirectRoute, ?string $postLogoutRoute, string $refusal): void
    {
        // Given
        $client = new SelfClient(self::router(), 'https://op.example', $redirectRoute, $postLogoutRoute, self::SECRET, self::KERNEL_SECRET);

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains($refusal);

        // When
        $client->declaration();
    }

    /**
     * @return iterable<string, array{string, ?string, string}>
     */
    public static function provideRoutesTheRouterWritesNoUrlFor(): iterable
    {
        yield 'an unknown route to come back to' => [
            'app_unknown',
            null,
            'The "beffroi" configuration key "self_client.redirect_route" names "app_unknown", a route the router writes no URL for:',
        ];
        yield 'an unknown route after a logout' => [
            'app_oidc_callback',
            'app_unknown',
            'The "beffroi" configuration key "self_client.post_logout_route" names "app_unknown", a route the router writes no URL for:',
        ];
        yield 'a route that needs a parameter' => [
            'app_tenant_callback',
            null,
            'The "beffroi" configuration key "self_client.redirect_route" names "app_tenant_callback", a route the router writes no URL for:',
        ];
    }

    private static function router(RequestContext $context = new RequestContext()): UrlGenerator
    {
        $routes = new RouteCollection();
        $routes->add('app_oidc_callback', new Route('/oidc/callback'));
        $routes->add('app_home', new Route('/'));
        $routes->add('app_tenant_callback', new Route('/{tenant}/oidc/callback'));

        return new UrlGenerator($routes, $context);
    }
}
