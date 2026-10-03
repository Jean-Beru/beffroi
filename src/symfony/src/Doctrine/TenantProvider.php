<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine;

use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Port\AmbientTenantInterface;
use function implode;
use function sprintf;
use Symfony\Contracts\Service\ResetInterface;

/**
 * The tenant of the current request or message: the row Doctrine manages, checked against the
 * configuration. An entity is not a service: the instance is forgotten when the kernel resets or the
 * entity manager is cleared.
 */
final class TenantProvider implements AmbientTenantInterface, ResetInterface
{
    private ?Tenant $tenant = null;

    public function __construct(
        private readonly TenantFactory $factory,
        private readonly EntityManagers $managers,
    ) {
    }

    /**
     * @throws TenantNotSynchronizedException
     */
    public function provide(): Tenant
    {
        if ($this->tenant !== null) {
            return $this->tenant;
        }
        $configured = $this->factory->create();
        $tenant = $this->managers->forClass(Tenant::class)->find(Tenant::class, $configured->id);
        if ($tenant === null) {
            throw TenantNotSynchronizedException::missing($configured->slug);
        }
        if (! $tenant->issuer->equals($configured->issuer)) {
            throw TenantNotSynchronizedException::differs($configured->slug, 'issuer', (string) $tenant->issuer, (string) $configured->issuer);
        }
        if ($tenant->name !== $configured->name) {
            throw TenantNotSynchronizedException::differs($configured->slug, 'name', $tenant->name, $configured->name);
        }
        if (! $tenant->authenticationContextPolicy->equals($configured->authenticationContextPolicy)) {
            throw TenantNotSynchronizedException::differs(
                $configured->slug,
                'authentication_classes',
                implode(' ', $tenant->authenticationContextPolicy->names()),
                implode(' ', $configured->authenticationContextPolicy->names()),
            );
        }

        if (! $tenant->look->equals($configured->look)) {
            throw TenantNotSynchronizedException::differs($configured->slug, 'look', self::described($tenant->look), self::described($configured->look));
        }

        return $this->tenant = $tenant;
    }

    /**
     * The look of a tenant in one line, for the refusal above to say which of the two is which; nothing
     * else reads it, which is why it is here and not on the value object.
     */
    private static function described(TenantLook $look): string
    {
        if (! $look->isDeclared()) {
            return 'none';
        }
        $parts = [];
        if ($look->logoUri !== null) {
            $parts[] = 'logo ' . $look->logoUri->value;
        }
        if ($look->primaryColor !== null) {
            $parts[] = sprintf('%s on %s', $look->primaryColor, (string) $look->primaryContentColor);
        }

        return implode(', ', $parts);
    }

    public function reset(): void
    {
        $this->tenant = null;
    }

    public function onClear(): void
    {
        $this->reset();
    }
}
