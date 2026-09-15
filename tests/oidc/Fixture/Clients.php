<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;

final class Clients
{
    public const string SECRET = 'a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3e7f2a6b0c4d8e1f5a9b3c7d0e4f8a2b6';

    public static function confidential(Tenant $tenant, PasswordHash $secretHash, TokenEndpointAuthMethod $method = TokenEndpointAuthMethod::ClientSecretBasic, string $clientId = 'oidc-demo'): Client
    {
        return new Client(
            $tenant,
            $clientId,
            'OIDC demo',
            $method,
            $secretHash,
            [new RedirectUri('https://demo.localhost/login/check')],
            [new RedirectUri('https://demo.localhost/')],
            [GrantType::AuthorizationCode, GrantType::RefreshToken],
            [new Scope('openid'), new Scope('profile'), new Scope('email')],
        );
    }

    public static function public(Tenant $tenant, string $clientId = 'spa'): Client
    {
        return new Client($tenant, $clientId, 'Single page application', TokenEndpointAuthMethod::None, null, [new RedirectUri('https://spa.example/callback')]);
    }
}
