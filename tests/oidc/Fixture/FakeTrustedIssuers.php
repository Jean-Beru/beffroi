<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Port\TrustedIssuersInterface;

/**
 * The issuers a tenant trusts, held for the life of the process: what the tests wire where a deployment wires
 * the ones its configuration declares.
 */
final class FakeTrustedIssuers implements TrustedIssuersInterface
{
    /**
     * @var array<string, array<string, TrustedIssuer>> by tenant slug, then by issuer
     */
    private array $issuers = [];

    public function trust(Tenant $tenant, TrustedIssuer $issuer): void
    {
        $this->issuers[$tenant->slug][$issuer->issuer] = $issuer;
    }

    public function find(Tenant $tenant, string $issuer): ?TrustedIssuer
    {
        return $this->issuers[$tenant->slug][$issuer] ?? null;
    }
}
