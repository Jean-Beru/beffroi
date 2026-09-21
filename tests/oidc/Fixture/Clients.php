<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Scope\Scope;

final class Clients
{
    public const string SECRET = 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3e7f2a6b0c4d8e1f5a9b3c7d0e4f8a2b6';

    public static function confidential(Tenant $tenant, PasswordHash $secretHash, ?ClientAuthenticationMethodInterface $method = null, string $clientId = 'oidc-demo', bool $requiresPkce = true, AccessTokenFormat $accessTokenFormat = AccessTokenFormat::Jwt): Client
    {
        return new Client(
            $tenant,
            $clientId,
            'OIDC demo',
            $method ?? Methods::clientSecretBasic(),
            new HashedClientSecret($secretHash),
            [new RedirectUri('https://demo.localhost/login/check')],
            [new RedirectUri('https://demo.localhost/')],
            [GrantType::AuthorizationCode, GrantType::RefreshToken],
            [new Scope('openid'), new Scope('profile'), new Scope('email')],
            requiresPkce: $requiresPkce,
            accessTokenFormat: $accessTokenFormat,
        );
    }

    public static function public(Tenant $tenant, string $clientId = 'spa'): Client
    {
        return new Client($tenant, $clientId, 'Single page application', Methods::none(), null, [new RedirectUri('https://spa.example/callback')]);
    }

    /**
     * A client that signs its assertions with a key of its own (OIDC Core §9, "private_key_jwt"),
     * publishing its JWK Set inline or behind a "jwks_uri".
     */
    public static function withKeys(Tenant $tenant, string $clientId = 'key-client', ?ClientJwks $jwks = null, ?ClientUri $jwksUri = null): Client
    {
        return new Client(
            $tenant,
            $clientId,
            'Client with a key',
            Methods::privateKeyJwt(),
            null,
            [new RedirectUri('https://key.example/callback')],
            jwks: $jwksUri === null ? $jwks ?? ClientAssertions::publishedKeys() : null,
            jwksUri: $jwksUri,
        );
    }

    /**
     * A client that signs its assertions with the secret it registered (OIDC Core §9,
     * "client_secret_jwt"), which the provider therefore holds in clear.
     */
    public static function withSharedSecret(Tenant $tenant, string $clientId = 'mac-client', string $secret = self::SECRET): Client
    {
        return new Client(
            $tenant,
            $clientId,
            'Client with a shared secret',
            Methods::clientSecretJwt(),
            new SharedClientSecret($secret),
            [new RedirectUri('https://mac.example/callback')],
        );
    }

    /**
     * A client the logout page loads in a frame when a session it signed in ends (Front-Channel Logout
     * 1.0 §3), which reads "iss" and "sid" only when it said so.
     */
    public static function withFrontChannelLogout(Tenant $tenant, string $clientId = 'spa', string $logoutUri = 'https://spa.example/frontchannel-logout', bool $sessionRequired = false): Client
    {
        return new Client(
            $tenant,
            $clientId,
            'Single page application',
            Methods::none(),
            null,
            [new RedirectUri('https://spa.example/callback')],
            frontChannelLogoutUri: new ClientUri($logoutUri),
            frontChannelLogoutSessionRequired: $sessionRequired,
        );
    }

    /**
     * A client the provider tells when a session it signed in ends (Back-Channel Logout 1.0 §2.2).
     */
    public static function withBackChannelLogout(Tenant $tenant, string $clientId = 'spa', string $logoutUri = 'https://spa.example/backchannel-logout'): Client
    {
        return new Client(
            $tenant,
            $clientId,
            'Single page application',
            Methods::none(),
            null,
            [new RedirectUri('https://spa.example/callback')],
            backChannelLogoutUri: new ClientUri($logoutUri),
        );
    }
}
