<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tenant;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The tenant of the "heidi.tenant" configuration (architecture §5.1); its identifier derives from its
 * slug, so renaming the slug is creating another tenant.
 */
final readonly class TenantFactory
{
    /**
     * RFC 9562 §6.6, fixed for the life of the project.
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
