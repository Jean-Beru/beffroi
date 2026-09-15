<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tenant;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The one tenant of spike 1, built from the "heidi.tenant" configuration (architecture §5.1). Its identifier
 * is derived from its slug, so that every process, every deployment and every row that will carry a
 * tenant_id agree on it without a database: renaming the slug is creating another tenant.
 */
final readonly class TenantFactory
{
    /**
     * RFC 9562 §6.6 name-based identifiers need a namespace; this one is fixed for the life of the project.
     */
    private const string NAMESPACE = '55ade059-fda4-45f4-96ca-43dc8ef74d3e';

    public function __construct(
        private string $issuer,
        private string $slug,
        private ?string $name,
        private ClockInterface $clock,
    ) {
    }

    public function create(): Tenant
    {
        $issuer = new Issuer($this->issuer);

        return new Tenant(self::identifier($this->slug), $this->slug, $issuer, $this->name ?? $issuer->host, $this->clock->now());
    }

    public static function identifier(string $slug): Uuid
    {
        return Uuid::v5(Uuid::fromString(self::NAMESPACE), $slug);
    }
}
