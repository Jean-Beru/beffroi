<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Port\EndpointLocatorInterface;

/**
 * Where the endpoints of a tenant are served in the tests: under the issuer, at the paths the
 * application routes them to.
 */
final class Endpoints implements EndpointLocatorInterface
{
    public function locate(Tenant $tenant): ProviderEndpoints
    {
        $issuer = $tenant->issuer->value;

        return new ProviderEndpoints($issuer . '/authorize', $issuer . '/token', $issuer . '/userinfo', $issuer . '/jwks', $issuer . '/logout', $issuer . '/introspect', $issuer . '/revoke');
    }

    public static function of(Tenant $tenant): ProviderEndpoints
    {
        return new self()
            ->locate($tenant);
    }
}
