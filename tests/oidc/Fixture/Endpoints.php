<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ClientConfigurationEndpointInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;

/**
 * RFC 8705 §5
 */
final readonly class Endpoints implements ClientConfigurationEndpointInterface, EndpointLocatorInterface, MutualTlsEndpointLocatorInterface
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

    public function clientConfigurationFor(Tenant $tenant, string $clientId): string
    {
        return $tenant->issuer->value . '/register/' . $clientId;
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
            $origin . '/register',
        );
    }
}
