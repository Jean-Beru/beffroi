<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;

final readonly class DeclaredUpstreamProviders implements UpstreamIdentityProvidersInterface
{
    /**
     * @param list<UpstreamIdentityProvider> $providers
     */
    public function __construct(
        private array $providers,
    ) {
    }

    public function of(Tenant $tenant): array
    {
        return $this->providers;
    }

    public function find(Tenant $tenant, string $entityId): ?UpstreamIdentityProvider
    {
        foreach ($this->providers as $provider) {
            if ($provider->entityId === $entityId) {
                return $provider;
            }
        }

        return null;
    }
}
