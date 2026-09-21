<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Discovery\DiscoveryHandler;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
use Heidi\Oidc\Tests\Fixture\Logins;
use Heidi\Oidc\Tests\Fixture\ServedChannels;
use Heidi\Oidc\Tests\Fixture\ServedModes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DiscoveryHandlerTest extends TestCase
{
    private DiscoveryHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::both(), self::grants());
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
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::both(), self::grants(), $lifetime);

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
        new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::both(), self::grants(), -1);
    }

    /**
     * OIDC Discovery §3, RFC 8414 §2: "grant_types_supported" is what the token endpoint serves, the grants
     * tagged into it, and "token_endpoint_auth_methods_supported" what the client authenticator implements.
     */
    #[Test]
    public function theDocumentAnnouncesTheGrantsWiredAndTheMethodsImplemented(): void
    {
        // When
        $document = $this->handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertSame(['authorization_code', 'refresh_token'], $document['grant_types_supported']);
        static::assertSame(['client_secret_basic', 'client_secret_post', 'none'], $document['token_endpoint_auth_methods_supported']);
        static::assertSame(['client_secret_basic', 'client_secret_post', 'none'], $document['revocation_endpoint_auth_methods_supported']);
        static::assertSame(['client_secret_basic', 'client_secret_post'], $document['introspection_endpoint_auth_methods_supported']);
    }

    /**
     * A deployment that serves the authorization code grant only says so, and "offline_access" with it
     * (OIDC Core §11: the scope asks for a refresh token).
     */
    #[Test]
    public function aProviderWithoutTheRefreshTokenGrantAnnouncesNeitherItNorOfflineAccess(): void
    {
        // Given
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::both(), [new FakeGrant(GrantType::AuthorizationCode)]);

        // When
        $document = $handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertSame(['authorization_code'], $document['grant_types_supported']);
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $document['scopes_supported']);
    }

    /**
     * Issue #98: what the document announces is what the integration wired, here the two ways of
     * answering the authorization endpoint the bundle serves (Form Post Response Mode §2).
     */
    #[Test]
    public function theDocumentAnnouncesTheResponseModesTheIntegrationWired(): void
    {
        // When
        $document = $this->handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertSame(['query', 'form_post'], $document['response_modes_supported']);
    }

    /**
     * A deployment that wired no way of posting a response announces none: the document follows the
     * endpoint, never an enumeration of the module.
     */
    #[Test]
    public function aProviderThatPostsNoResponseAnnouncesTheDefaultModeAlone(): void
    {
        // Given
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryOnly(), ServedChannels::both(), self::grants());

        // When
        $document = $handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertSame(['query'], $document['response_modes_supported']);
    }

    /**
     * Issue #98 again, on the two ways of telling a client that a session ended (Back-Channel Logout 1.0
     * §3, Front-Channel Logout 1.0 §3): the bundle wires both, so the document announces both.
     */
    #[Test]
    public function theDocumentAnnouncesTheLogoutChannelsTheIntegrationWired(): void
    {
        // When
        $document = $this->handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertTrue($document['backchannel_logout_supported']);
        static::assertTrue($document['frontchannel_logout_supported']);
    }

    /**
     * A deployment that wires no logout page announces no front channel, and still announces the one it
     * serves.
     */
    #[Test]
    public function aProviderThatLoadsNoLogoutPageAnnouncesTheBackChannelAlone(): void
    {
        // Given
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::backChannelOnly(), self::grants());

        // When
        $document = $handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertTrue($document['backchannel_logout_supported']);
        static::assertFalse($document['frontchannel_logout_supported']);
    }

    /**
     * A deployment that tells no client anything announces neither, rather than promising a channel
     * nothing serves.
     */
    #[Test]
    public function aProviderThatTellsNobodyAnnouncesNoChannel(): void
    {
        // Given
        $handler = new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::none(), self::grants());

        // When
        $document = $handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertFalse($document['backchannel_logout_supported']);
        static::assertFalse($document['frontchannel_logout_supported']);
    }

    #[Test]
    public function aTokenEndpointWithoutAGrantIsRefusedAtConstruction(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token endpoint serves at least one grant.');

        // When
        new DiscoveryHandler(self::locator(), new StandardClaimsProvider(), Logins::passwordAndPasskey(), ServedModes::queryAndFormPost(), ServedChannels::both(), []);
    }

    /**
     * @return list<FakeGrant> the two grants of the token endpoint, as the bundle tags them
     */
    private static function grants(): array
    {
        return [new FakeGrant(GrantType::AuthorizationCode), new FakeGrant(GrantType::RefreshToken)];
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
