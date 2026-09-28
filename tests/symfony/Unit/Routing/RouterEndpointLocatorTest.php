<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Routing;

use DateTimeImmutable;
use Heidi\Bundle\Routing\RouterEndpointLocator;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Exception\InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
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
        // Given
        $locator = new RouterEndpointLocator(self::router(''));

        // When
        $endpoints = $locator->locate(self::tenant('https://op.example'));

        // Then
        static::assertSame('https://op.example/authorize', $endpoints->authorization);
        static::assertSame('https://op.example/token', $endpoints->token);
        static::assertSame('https://op.example/userinfo', $endpoints->userinfo);
        static::assertSame('https://op.example/jwks', $endpoints->jwks);
        static::assertSame('https://op.example/logout', $endpoints->endSession);
        static::assertSame('https://op.example/introspect', $endpoints->introspection);
        static::assertSame('https://op.example/revoke', $endpoints->revocation);
        static::assertSame('https://op.example/par', $endpoints->pushedAuthorizationRequest);
        static::assertSame('https://op.example/device_authorization', $endpoints->deviceAuthorization);
        static::assertSame('https://op.example/device', $endpoints->deviceVerification);
        static::assertSame('https://op.example/backchannel_authentication', $endpoints->backchannelAuthentication);
        static::assertSame('https://op.example/account/approvals', $endpoints->backchannelApproval);
        static::assertSame('https://op.example/register', $endpoints->clientRegistration);
    }

    /**
     * The request came in on another host, or on a port the issuer does not name: the issuer wins.
     */
    #[Test]
    public function theHostOfTheRequestIsIgnored(): void
    {
        // Given
        $locator = new RouterEndpointLocator(self::router('', new RequestContext('', 'GET', 'attacker.example', 'http', 8080)));

        // When
        $endpoints = $locator->locate(self::tenant('https://op.example:8443'));

        // Then
        static::assertSame('https://op.example:8443/token', $endpoints->token);
    }

    /**
     * An issuer with a path, the routes mounted under it (OIDC Discovery §4.1).
     */
    #[Test]
    public function anIssuerWithAPathHasItsRoutesUnderThatPath(): void
    {
        // Given
        $locator = new RouterEndpointLocator(self::router('/tenant1'));

        // When
        $endpoints = $locator->locate(self::tenant('https://op.example/tenant1'));

        // Then
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
        // Given
        $locator = new RouterEndpointLocator(self::router('/auth'));

        // When
        try {
            $locator->locate(self::tenant('https://op.example'));
            static::fail('The routes are not under the issuer.');
        } catch (LogicException $exception) {
            // Then
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
        // Given
        $locator = new RouterEndpointLocator(self::router(''));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $locator->locate(self::tenant('http://localhost:8000'));
    }

    /**
     * RFC 8705 §5: the endpoints located again on the host whose listener asks for a client certificate,
     * same paths, other origin, so that the two sets cannot say different things.
     */
    #[Test]
    public function theAliasesAreTheSameRoutesOnTheHostThatAsksForACertificate(): void
    {
        // Given
        $locator = new RouterEndpointLocator(self::router('/tenant1'), 'https://mtls.op.example');

        // When
        $endpoints = $locator->locateMutualTls(self::tenant('https://op.example/tenant1'));

        // Then
        static::assertSame('https://mtls.op.example/tenant1/token', $endpoints?->token);
        static::assertSame('https://mtls.op.example/tenant1/userinfo', $endpoints->userinfo);
        static::assertSame('https://mtls.op.example/tenant1/introspect', $endpoints->introspection);
        static::assertSame('https://mtls.op.example/tenant1/revoke', $endpoints->revocation);
        static::assertSame('https://mtls.op.example/tenant1/par', $endpoints->pushedAuthorizationRequest);
        static::assertSame('https://mtls.op.example/tenant1/device_authorization', $endpoints->deviceAuthorization);
    }

    /**
     * A deployment that serves one host names no origin, and an environment variable nobody set is an
     * empty one: both are "no such host", and the document announces no alias.
     */
    #[Test]
    #[DataProvider('provideNoMutualTlsHost')]
    public function aDeploymentWithoutSuchAHostLocatesNone(?string $origin): void
    {
        // Given
        $locator = new RouterEndpointLocator(self::router(''), $origin);

        // When / Then
        static::assertNull($locator->locateMutualTls(self::tenant('https://op.example')));
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideNoMutualTlsHost(): iterable
    {
        yield 'nothing configured' => [null];

        yield 'an environment variable nobody set' => [''];
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
        $routes->add('heidi_protocol_introspection', new Route($prefix . '/introspect'));
        $routes->add('heidi_protocol_revocation', new Route($prefix . '/revoke'));
        $routes->add('heidi_protocol_pushed_authorization_request', new Route($prefix . '/par'));
        $routes->add('heidi_protocol_device_authorization', new Route($prefix . '/device_authorization'));
        $routes->add('heidi_interaction_device', new Route($prefix . '/device'));
        $routes->add('heidi_protocol_backchannel_authentication', new Route($prefix . '/backchannel_authentication'));
        $routes->add('heidi_interaction_account_approvals', new Route($prefix . '/account/approvals'));
        $routes->add('heidi_protocol_client_registration', new Route($prefix . '/register'));

        return new UrlGenerator($routes, $context ?? new RequestContext());
    }

    private static function tenant(string $issuer): Tenant
    {
        return new Tenant(Uuid::v7(), 'default', new Issuer($issuer), 'Test', new DateTimeImmutable('2026-09-15T10:00:00+00:00'));
    }
}
