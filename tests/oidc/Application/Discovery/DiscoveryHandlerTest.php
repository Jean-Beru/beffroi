<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Discovery\DiscoveryHandler;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DiscoveryHandlerTest extends TestCase
{
    private DiscoveryHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider());
    }

    /**
     * OIDC Discovery §3: "issuer" is the tenant's, the endpoints are where the integration serves this tenant.
     */
    #[Test]
    public function theDocumentNamesTheIssuerAndTheEndpointsOfTheTenant(): void
    {
        // When
        $document = $this->handler->handle(Fixtures::tenant('acme', 'https://as.example/acme'))->toArray();

        // Then
        static::assertSame('https://as.example/acme', $document['issuer']);
        static::assertSame('https://as.example/acme/authorize', $document['authorization_endpoint']);
        static::assertSame('https://as.example/acme/token', $document['token_endpoint']);
        static::assertSame('https://as.example/acme/userinfo', $document['userinfo_endpoint']);
        static::assertSame('https://as.example/acme/jwks', $document['jwks_uri']);
        static::assertSame('https://as.example/acme/logout', $document['end_session_endpoint']);
        static::assertSame('https://as.example/acme/introspect', $document['introspection_endpoint']);
        static::assertSame('https://as.example/acme/revoke', $document['revocation_endpoint']);
    }

    /**
     * OIDC Discovery §3: "scopes_supported" is "openid", what the claims provider serves and
     * "offline_access" (OIDC Core §11); "claims_supported" is "sub" and what the claims provider may supply.
     */
    #[Test]
    public function theDocumentAnnouncesTheScopesAndClaimsOfTheClaimsProvider(): void
    {
        // When
        $document = $this->handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone', 'offline_access'], $document['scopes_supported']);
        static::assertSame(['sub', ...new StandardClaimsProvider()->supportedClaims()], $document['claims_supported']);
    }

    /**
     * RFC 8414 §3: the metadata location follows the issuer of the tenant.
     */
    #[Test]
    public function theDocumentKnowsItsWellKnownLocation(): void
    {
        // When
        $metadata = $this->handler->handle(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame('https://as.example/.well-known/oauth-authorization-server/acme', $metadata->authorizationServerMetadataUrl());
    }

    /**
     * The cache lifetime is one hour by default.
     */
    #[Test]
    public function theDocumentIsCachedForOneHourByDefault(): void
    {
        // When
        $metadata = $this->handler->handle(Fixtures::tenant());

        // Then
        static::assertSame([
            'Cache-Control' => 'public, max-age=3600',
        ], $metadata->headers);
    }

    /**
     * The endpoints are asked for the tenant served, not for another one.
     */
    #[Test]
    public function eachTenantGetsItsOwnIssuerAndEndpoints(): void
    {
        // When
        $acme = $this->handler->handle(Fixtures::tenant('acme', 'https://id.acme.example'))->toArray();
        $globex = $this->handler->handle(Fixtures::tenant('globex', 'https://id.globex.example'))->toArray();

        // Then
        static::assertSame('https://id.acme.example', $acme['issuer']);
        static::assertSame('https://id.acme.example/token', $acme['token_endpoint']);
        static::assertSame('https://id.globex.example', $globex['issuer']);
        static::assertSame('https://id.globex.example/token', $globex['token_endpoint']);
    }

    /**
     * The document differs from one tenant to the next by its issuer and endpoints only.
     */
    #[Test]
    public function theDocumentsOfTwoTenantsDifferByTheirLocationsOnly(): void
    {
        // Given
        $locations = ['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint', 'introspection_endpoint', 'revocation_endpoint'];

        // When
        $acme = $this->handler->handle(Fixtures::tenant('acme', 'https://id.acme.example'))->toArray();
        $globex = $this->handler->handle(Fixtures::tenant('globex', 'https://id.globex.example'))->toArray();

        // Then
        foreach ($locations as $location) {
            unset($acme[$location], $globex[$location]);
        }
        static::assertSame($acme, $globex);
    }

    /**
     * The cache lifetime is the deployment's, zero meaning "revalidate every time".
     */
    #[Test]
    #[DataProvider('provideLifetimes')]
    public function theLifetimeIsAnOption(int $lifetime, string $cacheControl): void
    {
        // Given
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), $lifetime);

        // When
        $metadata = $handler->handle(Fixtures::tenant());

        // Then
        static::assertSame([
            'Cache-Control' => $cacheControl,
        ], $metadata->headers);
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'one minute' => [60, 'public, max-age=60'];
        yield 'zero' => [0, 'public, max-age=0'];
    }

    /**
     * A negative lifetime is refused at construction, not on the first request.
     */
    #[Test]
    public function aNegativeLifetimeIsRefusedAtConstruction(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('number of seconds');

        // When
        new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), -1);
    }

    /**
     * The endpoints under the issuer of the tenant, at the default paths of architecture §5.2.
     */
    private static function locator(): EndpointLocatorInterface
    {
        return new class() implements EndpointLocatorInterface {
            public function locate(Tenant $tenant): ProviderEndpoints
            {
                $issuer = $tenant->issuer->value;

                return new ProviderEndpoints($issuer . '/authorize', $issuer . '/token', $issuer . '/userinfo', $issuer . '/jwks', $issuer . '/logout', $issuer . '/introspect', $issuer . '/revoke');
            }
        };
    }
}
