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
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DiscoveryHandlerTest extends TestCase
{
    /**
     * OIDC Discovery §3: "issuer" is the tenant's, the endpoints are where the integration serves this
     * tenant, "scopes_supported" is "openid", what the claims provider serves and "offline_access"
     * (OIDC Core §11), "claims_supported" is "sub" and what the claims provider may supply.
     */
    #[Test]
    public function itAssemblesTheDocumentOfATenant(): void
    {
        $tenant = Fixtures::tenant('acme', 'https://as.example/acme');
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider());

        $document = $handler->handle($tenant)
            ->toArray();

        static::assertSame('https://as.example/acme', $document['issuer']);
        static::assertSame('https://as.example/acme/authorize', $document['authorization_endpoint']);
        static::assertSame('https://as.example/acme/token', $document['token_endpoint']);
        static::assertSame('https://as.example/acme/userinfo', $document['userinfo_endpoint']);
        static::assertSame('https://as.example/acme/jwks', $document['jwks_uri']);
        static::assertSame('https://as.example/acme/logout', $document['end_session_endpoint']);
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone', 'offline_access'], $document['scopes_supported']);
        static::assertSame(['sub', ...new StandardClaimsProvider()->supportedClaims()], $document['claims_supported']);
        static::assertSame([
            'Cache-Control' => 'public, max-age=3600',
        ], $handler->handle($tenant)
            ->headers);
        static::assertSame('https://as.example/.well-known/oauth-authorization-server/acme', $handler->handle($tenant)->authorizationServerMetadataUrl());
    }

    /**
     * The endpoints are asked for the tenant served, not for another one; the document differs from
     * one tenant to the next by its issuer and endpoints only.
     */
    #[Test]
    public function eachTenantGetsItsOwnDocument(): void
    {
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider());
        $acme = $handler->handle(Fixtures::tenant('acme', 'https://id.acme.example'))->toArray();
        $globex = $handler->handle(Fixtures::tenant('globex', 'https://id.globex.example'))->toArray();

        static::assertSame('https://id.acme.example', $acme['issuer']);
        static::assertSame('https://id.acme.example/token', $acme['token_endpoint']);
        static::assertSame('https://id.globex.example', $globex['issuer']);
        static::assertSame('https://id.globex.example/token', $globex['token_endpoint']);
        unset($acme['issuer'], $acme['authorization_endpoint'], $acme['token_endpoint'], $acme['userinfo_endpoint'], $acme['jwks_uri'], $acme['end_session_endpoint'], $globex['issuer'], $globex['authorization_endpoint'], $globex['token_endpoint'], $globex['userinfo_endpoint'], $globex['jwks_uri'], $globex['end_session_endpoint']);

        static::assertSame($acme, $globex);
    }

    /**
     * The cache lifetime is the deployment's, one hour by default, zero meaning "revalidate every time";
     * a negative one is refused at construction, not on the first request.
     */
    #[Test]
    public function theLifetimeIsAnOptionCheckedAtConstruction(): void
    {
        static::assertSame([
            'Cache-Control' => 'public, max-age=60',
        ], new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), 60)->handle(Fixtures::tenant())->headers);
        static::assertSame([
            'Cache-Control' => 'public, max-age=0',
        ], new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), 0)->handle(Fixtures::tenant())->headers);

        try {
            new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), -1);
            static::fail('A negative lifetime is refused.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('number of seconds', $e->getMessage());
        }
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

                return new ProviderEndpoints($issuer . '/authorize', $issuer . '/token', $issuer . '/userinfo', $issuer . '/jwks', $issuer . '/logout');
            }
        };
    }
}
