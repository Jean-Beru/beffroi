<?php

declare(strict_types=1);

namespace App\Demonstration;

use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use LogicException;

/**
 * Where this provider serves, asked of the provider itself (OIDC Discovery §3): the demonstration
 * watches and calls the endpoints of the tenant it is running against, and writes no address of its own.
 */
final readonly class ProviderEndpointsOfTheTenant
{
    public function __construct(
        private AmbientTenantInterface $tenants,
        private EndpointLocatorInterface $locator,
    ) {
    }

    /**
     * @throws LogicException when the routes of the provider are not mounted under its issuer
     */
    public function endpoints(): ProviderEndpoints
    {
        return $this->locator->locate($this->tenants->provide());
    }

    public function issuer(): string
    {
        return (string) $this->tenants->provide()->issuer;
    }
}
