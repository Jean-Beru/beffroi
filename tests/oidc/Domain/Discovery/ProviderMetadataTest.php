<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Discovery;

use function array_keys;
use function array_map;
use function array_slice;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProviderMetadataTest extends TestCase
{
    /**
     * OIDC Discovery §3: the members, in the order the section lists them, then "code_challenge_methods_supported"
     * (RFC 8414 §2), "authorization_response_iss_parameter_supported" (RFC 9207 §3) and "end_session_endpoint"
     * (RP-Initiated Logout §2.1). Only what the provider does: "code", "query", "S256", "public", "RS256",
     * the three client authentication methods of RFC 6749 §2.3, no request object.
     */
    #[Test]
    public function itDescribesWhatTheProviderDoesAndNothingElse(): void
    {
        $metadata = self::metadata();

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
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'claims_supported' => ['sub', 'name', 'email', 'email_verified'],
            'claims_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => ['S256'],
            'authorization_response_iss_parameter_supported' => true,
            'end_session_endpoint' => 'https://id.acme.example/logout',
        ], $metadata->toArray());
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
        $json = self::metadata()->toJson();

        static::assertStringContainsString('"issuer":"https://id.acme.example",', $json);
        static::assertStringContainsString('"claims_parameter_supported":true,"request_parameter_supported":false,"request_uri_parameter_supported":false,', $json);
        static::assertStringContainsString('"authorization_response_iss_parameter_supported":true,', $json);
        static::assertStringContainsString('"response_types_supported":["code"],', $json);
        static::assertSame(self::metadata()->toArray(), json_decode($json, true, 4, JSON_THROW_ON_ERROR));
        static::assertTrue(json_decode($json, true, 4, JSON_THROW_ON_ERROR)['authorization_response_iss_parameter_supported']);
    }

    /**
     * OIDC Discovery §3: "openid" MUST be supported and "sub" is always a claim; both come first whatever
     * the integration lists, and a scope or a claim listed twice is announced once.
     */
    #[Test]
    public function openidAndSubComeFirstAndOnce(): void
    {
        $metadata = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [new Scope('email'), new Scope('openid'), new Scope('email')], ['email', 'sub', 'email'], 60);

        static::assertSame(['openid', 'email'], array_map(static fn (Scope $scope): string => $scope->value, $metadata->scopesSupported));
        static::assertSame(['sub', 'email'], $metadata->claimsSupported);

        $bare = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], 60);
        static::assertSame(['openid'], $bare->toArray()['scopes_supported']);
        static::assertSame(['sub'], $bare->toArray()['claims_supported']);
    }

    /**
     * OIDC Discovery §4.1 appends the well-known path to the issuer; RFC 8414 §3 inserts it between the
     * host and the path of the issuer. Both are the same location when the issuer has no path.
     */
    #[Test]
    public function theWellKnownLocationsFollowTheIssuer(): void
    {
        $metadata = self::metadata();
        static::assertSame('https://id.acme.example/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://id.acme.example/.well-known/oauth-authorization-server', $metadata->authorizationServerMetadataUrl());

        $withPath = new ProviderMetadata(new Issuer('https://as.example:8443/tenants/acme'), self::endpoints(), [], [], 60);
        static::assertSame('https://as.example:8443/tenants/acme/.well-known/openid-configuration', $withPath->openIdConfigurationUrl());
        static::assertSame('https://as.example:8443/.well-known/oauth-authorization-server/tenants/acme', $withPath->authorizationServerMetadataUrl());
        static::assertSame('https://as.example:8443/tenants/acme', $withPath->toArray()['issuer']);
    }

    /**
     * The cache lifetime is a number of seconds, zero meaning "revalidate every time"; a claim name is
     * never empty.
     */
    #[Test]
    public function itRefusesANegativeLifetimeAndAnEmptyClaimName(): void
    {
        static::assertSame([
            'Cache-Control' => 'public, max-age=0',
        ], new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], 0)->headers);

        try {
            new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [], -1);
            static::fail('A negative lifetime is refused.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('number of seconds', $e->getMessage());
        }
        try {
            new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), [], [''], 60);
            static::fail('An empty claim name is refused.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('A supported claim has a name.', $e->getMessage());
        }
    }

    /**
     * What Symfony's OidcDiscovery checks before it uses a document: the "issuer" equals the configured
     * one, and every endpoint it reads is over HTTPS, the token endpoint even on loopback. The document
     * of a loopback issuer in development passes those checks too.
     */
    #[Test]
    public function itPassesTheChecksOfSymfonyOidcDiscovery(): void
    {
        foreach (['https://id.acme.example', 'https://op.localhost'] as $issuer) {
            $document = new ProviderMetadata(new Issuer($issuer), new ProviderEndpoints($issuer . '/authorize', $issuer . '/token', $issuer . '/userinfo', $issuer . '/jwks', $issuer . '/logout'), [], [], 60)->toArray();

            static::assertSame($issuer, $document['issuer']);
            foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint'] as $endpoint) {
                static::assertIsString($document[$endpoint]);
                static::assertStringStartsWith('https://', $document[$endpoint]);
            }
            static::assertTrue($document['authorization_response_iss_parameter_supported']);
        }
        static::assertSame(['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'], array_slice(array_keys(self::metadata()->toArray()), 0, 5));
    }

    private static function metadata(): ProviderMetadata
    {
        return new ProviderMetadata(
            new Issuer('https://id.acme.example'),
            self::endpoints(),
            [new Scope('openid'), new Scope('profile'), new Scope('email'), new Scope('offline_access')],
            ['name', 'email', 'email_verified'],
            3600,
        );
    }

    private static function endpoints(): ProviderEndpoints
    {
        return new ProviderEndpoints('https://id.acme.example/authorize', 'https://id.acme.example/token', 'https://id.acme.example/userinfo', 'https://id.acme.example/jwks', 'https://id.acme.example/logout');
    }
}
