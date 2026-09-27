<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MutualTlsEndpointLocatorInterface;

/**
 * Where the endpoints of a tenant are served in the tests: under the issuer, at the paths the
 * application routes them to, and on the host that asks for a client certificate when the test wires one
 * (RFC 8705 §5).
 */
final readonly class Endpoints implements EndpointLocatorInterface, MutualTlsEndpointLocatorInterface
{
    public function __construct(
        private ?string $mutualTlsOrigin = null,
    ) {
    }

    public function locate(Tenant $tenant): ProviderEndpoints
    {
        return self::under($tenant->issuer->value);
    }

    public function locateMutualTls(Tenant $tenant): ?ProviderEndpoints
    {
        return $this->mutualTlsOrigin === null ? null : self::under($this->mutualTlsOrigin);
    }

    public static function of(Tenant $tenant): ProviderEndpoints
    {
        return new self()->locate($tenant);
    }

    private static function under(string $origin): ProviderEndpoints
    {
        return new ProviderEndpoints(
            $origin . '/authorize',
            $origin . '/token',
            $origin . '/userinfo',
            $origin . '/jwks',
            $origin . '/logout',
            $origin . '/introspect',
            $origin . '/revoke',
            $origin . '/par',
            $origin . '/device_authorization',
            $origin . '/device',
            $origin . '/backchannel_authentication',
            $origin . '/account/approvals',
        );
    }
}
