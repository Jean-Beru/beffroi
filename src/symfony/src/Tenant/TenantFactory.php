<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tenant;

use Beffroi\Bundle\Configuration\TenantSection;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The tenant of the "beffroi.tenant" configuration (architecture §5.1); its identifier derives from its
 * slug, so renaming the slug is creating another tenant. Its "acr" policy is the configured classes in
 * their order (decision 0010); what the policy refuses refuses the start.
 */
final readonly class TenantFactory
{
    /**
     * RFC 9562 §6.6, fixed for the life of the project.
     */
    private const string NAMESPACE = '55ade059-fda4-45f4-96ca-43dc8ef74d3e';

    /**
     * @param array<array-key, string> $authenticationClasses class name to predicate, in order
     */
    public function __construct(
        private string $issuer,
        private string $slug,
        private ?string $name,
        private ClockInterface $clock,
        private array $authenticationClasses = TenantSection::DEFAULT_AUTHENTICATION_CLASSES,
    ) {
    }

    public function create(): Tenant
    {
        $issuer = new Issuer($this->issuer);

        return new Tenant(
            self::identifier($this->slug),
            $this->slug,
            $issuer,
            $this->name ?? $issuer->host,
            $this->clock->now(),
            $this->authenticationContextPolicy(),
        );
    }

    public function authenticationContextPolicy(): AuthenticationContextPolicy
    {
        $classes = [];
        foreach ($this->authenticationClasses as $name => $predicate) {
            $classes[] = new AuthenticationContextClass((string) $name, AuthenticationPredicate::from($predicate));
        }

        return new AuthenticationContextPolicy($classes);
    }

    public static function identifier(string $slug): Uuid
    {
        return Uuid::v5(Uuid::fromString(self::NAMESPACE), $slug);
    }
}
