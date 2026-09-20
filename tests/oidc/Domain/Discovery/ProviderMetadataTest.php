<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Discovery;

use function array_keys;
use function array_map;
use function array_slice;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProviderMetadataTest extends TestCase
{
    /**
     * OIDC Discovery §3: the members, in the order the section lists them, then those of RFC 8414 §2
     * ("code_challenge_methods_supported", the revocation and introspection endpoints with their
     * authentication methods, RFC 7009 §2.1 and RFC 7662 §2.1, and the algorithms of a signed introspection
     * response, RFC 9701 §6), "authorization_response_iss_parameter_supported" (RFC 9207 §3) and
     * "end_session_endpoint" (RP-Initiated Logout §2.1). Only what the provider does: "code", "query",
     * "S256", "public", "RS256", the three client authentication methods of RFC 6749 §2.3 at the token and
     * revocation endpoints, the two that prove a secret at introspection, the "acr" values given, no
     * request object.
     */
    #[Test]
    public function itDescribesWhatTheProviderDoesAndNothingElse(): void
    {
        // When
        $document = self::metadata()->toArray();

        // Then
        static::assertSame([
            'issuer' => 'https://id.acme.example',
            'authorization_endpoint' => 'https://id.acme.example/authorize',
            'token_endpoint' => 'https://id.acme.example/token',
            'userinfo_endpoint' => 'https://id.acme.example/userinfo',
            'jwks_uri' => 'https://id.acme.example/jwks',
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'acr_values_supported' => ['phrh', 'phr', '2', '1'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'claims_supported' => ['sub', 'name', 'email', 'email_verified'],
            'claims_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => ['S256'],
            'revocation_endpoint' => 'https://id.acme.example/revoke',
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'introspection_endpoint' => 'https://id.acme.example/introspect',
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'introspection_signing_alg_values_supported' => ['RS256'],
            'authorization_response_iss_parameter_supported' => true,
            'end_session_endpoint' => 'https://id.acme.example/logout',
        ], $document);
    }

    #[Test]
    public function itIsPubliclyCacheableForItsLifetime(): void
    {
        // When
        $metadata = self::metadata();

        // Then
        static::assertSame([
            'Cache-Control' => 'public, max-age=3600',
        ], $metadata->headers);
    }

    /**
     * The JSON a client reads: booleans as JSON booleans (oidc_login compares
     * "authorization_response_iss_parameter_supported" to true with ===), lists as JSON arrays, the
     * issuer byte for byte (OIDC Discovery §4.3).
     */
    #[Test]
    public function theJsonCarriesBooleansAndListsAsTheyAre(): void
    {
        // When
        $json = self::metadata()->toJson();

        // Then
        static::assertStringContainsString('"issuer":"https://id.acme.example",', $json);
        static::assertStringContainsString('"claims_parameter_supported":true,"request_parameter_supported":false,"request_uri_parameter_supported":false,', $json);
        static::assertStringContainsString('"authorization_response_iss_parameter_supported":true,', $json);
        static::assertStringContainsString('"response_types_supported":["code"],', $json);
    }

    #[Test]
    public function theJsonIsTheDocument(): void
    {
        // When
        $decoded = json_decode(self::metadata()->toJson(), true, 4, JSON_THROW_ON_ERROR);

        // Then
        static::assertSame(self::metadata()->toArray(), $decoded);
        static::assertTrue($decoded['authorization_response_iss_parameter_supported']);
    }

    /**
     * OIDC Discovery §3: "openid" MUST be supported and "sub" is always a claim; both come first whatever
     * the integration lists, and a scope or a claim listed twice is announced once.
     */
    #[Test]
    public function openidAndSubComeFirstAndOnce(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [new Scope('email'), new Scope('openid'), new Scope('email')], ['email', 'sub', 'email'], self::grantTypes(), self::methods(), ['1'], 60);

        // Then
        static::assertSame(['openid', 'email'], array_map(static fn (Scope $scope): string => $scope->value, $metadata->scopesSupported));
        static::assertSame(['sub', 'email'], $metadata->claimsSupported);
    }

    #[Test]
    public function openidAndSubAreAnnouncedEvenWhenTheIntegrationListsNothing(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], self::grantTypes(), self::methods(), ['1'], 60)->toArray();

        // Then
        static::assertSame(['openid'], $document['scopes_supported']);
        static::assertSame(['sub'], $document['claims_supported']);
    }

    /**
     * OIDC Discovery §4.1 appends the well-known path to the issuer; RFC 8414 §3 inserts it between the
     * host and the path of the issuer. Both are the same location when the issuer has no path.
     */
    #[Test]
    public function theWellKnownLocationsOfAnIssuerWithoutPathCoincide(): void
    {
        // When
        $metadata = self::metadata();

        // Then
        static::assertSame('https://id.acme.example/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://id.acme.example/.well-known/oauth-authorization-server', $metadata->authorizationServerMetadataUrl());
    }

    #[Test]
    public function theWellKnownLocationsOfAnIssuerWithAPathDiffer(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://as.example:8443/tenants/acme'), self::endpoints(), [], [], self::grantTypes(), self::methods(), ['1'], 60);

        // Then
        static::assertSame('https://as.example:8443/tenants/acme/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://as.example:8443/.well-known/oauth-authorization-server/tenants/acme', $metadata->authorizationServerMetadataUrl());
        static::assertSame('https://as.example:8443/tenants/acme', $metadata->toArray()['issuer']);
    }

    /**
     * The cache lifetime is a number of seconds, zero meaning "revalidate every time".
     */
    #[Test]
    public function aLifetimeOfZeroRevalidatesEveryTime(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], self::grantTypes(), self::methods(), ['1'], 0);

        // Then
        static::assertSame([
            'Cache-Control' => 'public, max-age=0',
        ], $metadata->headers);
    }

    #[Test]
    public function aNegativeLifetimeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('number of seconds');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], self::grantTypes(), self::methods(), ['1'], -1);
    }

    /**
     * RFC 8414 §2: the lists say what is wired, a grant, a method or a class listed twice counts once, nothing wired is a fault.
     */
    #[Test]
    public function theGrantTypesAndTheMethodsAreThoseGivenEachOnce(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], [GrantType::AuthorizationCode, GrantType::AuthorizationCode], [TokenEndpointAuthMethod::None, TokenEndpointAuthMethod::None], ['1', '1'], 60)->toArray();

        // Then
        static::assertSame(['authorization_code'], $document['grant_types_supported']);
        static::assertSame(['none'], $document['token_endpoint_auth_methods_supported']);
        static::assertSame(['none'], $document['revocation_endpoint_auth_methods_supported']);
        static::assertSame(['1'], $document['acr_values_supported']);
    }

    /**
     * OIDC Discovery §3: a provider that could assert no class would announce nothing; decision 0010 makes
     * every policy name the single factor, so the list is never empty.
     */
    #[Test]
    public function noAcrValueIsAFault(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider asserts at least one authentication context class (OIDC Discovery section 3).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], self::grantTypes(), self::methods(), [], 60);
    }

    /**
     * RFC 7662 §2.1: introspection takes the methods that prove a secret, among those the token endpoint takes.
     */
    #[Test]
    public function introspectionTakesTheSecretMethodsAmongThoseGiven(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], [GrantType::AuthorizationCode], [TokenEndpointAuthMethod::ClientSecretPost, TokenEndpointAuthMethod::None], ['1'], 60)->toArray();

        // Then
        static::assertSame(['client_secret_post'], $document['introspection_endpoint_auth_methods_supported']);
    }

    #[Test]
    public function noGrantTypeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider serves at least one grant type (RFC 8414 section 2).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], [], self::methods(), ['1'], 60);
    }

    #[Test]
    public function noAuthenticationMethodIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A token endpoint takes at least one client authentication method (RFC 8414 section 2).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], self::grantTypes(), [], ['1'], 60);
    }

    #[Test]
    public function anEmptyClaimNameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A supported claim has a name.');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [''], self::grantTypes(), self::methods(), ['1'], 60);
    }

    /**
     * What Symfony's OidcDiscovery checks before it uses a document: the "issuer" equals the configured
     * one, and every endpoint it reads is over HTTPS, the token endpoint even on loopback. The document
     * of a loopback issuer in development passes those checks too.
     */
    #[Test]
    #[DataProvider('provideIssuers')]
    public function itPassesTheChecksOfSymfonyOidcDiscovery(string $issuer): void
    {
        // When
        $document = new ProviderMetadata(new Issuer($issuer), new ProviderEndpoints($issuer . '/authorize', $issuer . '/token', $issuer . '/userinfo', $issuer . '/jwks', $issuer . '/logout', $issuer . '/introspect', $issuer . '/revoke'), [], [], self::grantTypes(), self::methods(), ['1'], 60)->toArray();

        // Then
        static::assertSame($issuer, $document['issuer']);
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint', 'introspection_endpoint', 'revocation_endpoint'] as $endpoint) {
            static::assertIsString($document[$endpoint]);
            static::assertStringStartsWith('https://', $document[$endpoint]);
        }
        static::assertTrue($document['authorization_response_iss_parameter_supported']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'public host' => ['https://id.acme.example'];
        yield 'loopback host' => ['https://op.localhost'];
    }

    #[Test]
    public function theIssuerAndTheEndpointsComeFirst(): void
    {
        // When
        $members = array_keys(self::metadata()->toArray());

        // Then
        static::assertSame(['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'], array_slice($members, 0, 5));
    }

    private static function metadata(): ProviderMetadata
    {
        return new ProviderMetadata(
            new Issuer('https://id.acme.example'),
            self::endpoints(),
            [new Scope('openid'), new Scope('profile'), new Scope('email'), new Scope('offline_access')],
            ['name', 'email', 'email_verified'],
            self::grantTypes(),
            self::methods(),
            ['phrh', 'phr', '2', '1'],
            3600,
        );
    }

    /**
     * @return list<GrantType>
     */
    private static function grantTypes(): array
    {
        return [GrantType::AuthorizationCode, GrantType::RefreshToken];
    }

    /**
     * @return list<TokenEndpointAuthMethod>
     */
    private static function methods(): array
    {
        return [TokenEndpointAuthMethod::ClientSecretBasic, TokenEndpointAuthMethod::ClientSecretPost, TokenEndpointAuthMethod::None];
    }

    private static function endpoints(): ProviderEndpoints
    {
        return new ProviderEndpoints('https://id.acme.example/authorize', 'https://id.acme.example/token', 'https://id.acme.example/userinfo', 'https://id.acme.example/jwks', 'https://id.acme.example/logout', 'https://id.acme.example/introspect', 'https://id.acme.example/revoke');
    }
}
