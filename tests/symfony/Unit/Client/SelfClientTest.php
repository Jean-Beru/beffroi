<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Client;

use App\Client\SelfClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

final class SelfClientTest extends TestCase
{
    private const string SECRET = 'the-secret-of-the-application-of-at-least-32-characters';

    private const string KERNEL_SECRET = 'the-secret-of-the-kernel';

    /**
     * Architecture §5.1
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
     * OIDC Discovery §4.1
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
     * Architecture §5.2
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

    #[Test]
    public function aRouteThatRequiresASchemeIsWrittenUnderTheOriginOfTheIssuer(): void
    {
        // Given
        $client = new SelfClient(
            self::router(new RequestContext('', 'GET', 'attacker.example', 'http', 8080)),
            'https://op.example',
            'app_secure_callback',
            null,
            self::SECRET,
            self::KERNEL_SECRET,
        );

        // When
        $declaration = $client->declaration();

        // Then
        static::assertSame(['https://op.example/secure/oidc/callback'], $declaration['redirect_uris']);
    }

    #[Test]
    public function aRouteThatRequiresAHostIsWrittenOnThatHost(): void
    {
        // Given
        $client = new SelfClient(self::router(), 'https://op.example', 'app_portal_callback', null, self::SECRET, self::KERNEL_SECRET);

        // When
        $declaration = $client->declaration();

        // Then
        static::assertSame(['https://portal.example/oidc/callback'], $declaration['redirect_uris']);
    }

    #[Test]
    public function theRouterIsGivenItsContextBack(): void
    {
        // Given
        $context = new RequestContext('', 'GET', 'app.example', 'http', 8080);
        $router = self::router($context);
        $client = new SelfClient($router, 'https://op.example', 'app_oidc_callback', 'app_home', self::SECRET, self::KERNEL_SECRET);

        // When
        $client->declaration();

        // Then
        static::assertSame($context, $router->getContext());
    }

    #[Test]
    public function theRouterIsGivenItsContextBackWhenARouteIsRefused(): void
    {
        // Given
        $context = new RequestContext('', 'GET', 'app.example', 'http', 8080);
        $router = self::router($context);
        $client = new SelfClient($router, 'https://op.example', 'app_unknown', null, self::SECRET, self::KERNEL_SECRET);

        // When
        try {
            $client->declaration();
        } catch (InvalidConfigurationException) {
        }

        // Then
        static::assertSame($context, $router->getContext());
    }

    /**
     * RP-Initiated Logout §3
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

    #[Test]
    public function theSecretOfTheKernelIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "self_client.secret" is the secret of the kernel: the application authenticates with a secret of its own, which its token requests carry over HTTP.');

        // When
        new SelfClient(self::router(), 'https://op.example', 'app_oidc_callback', null, self::SECRET, self::SECRET);
    }

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
        $routes->add('app_secure_callback', new Route('/secure/oidc/callback', schemes: ['https']));
        $routes->add('app_portal_callback', new Route('/oidc/callback', host: 'portal.example'));

        return new UrlGenerator($routes, $context);
    }
}
