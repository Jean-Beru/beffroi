<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Domain\Tenant\Tenant;
use function implode;
use LogicException;
use Symfony\Contracts\Service\ResetInterface;

/**
 * The tenant of the current request or message: the row Doctrine manages, checked against the
 * configuration. An entity is not a service: the instance is forgotten when the kernel resets or the
 * entity manager is cleared.
 */
final class TenantProvider implements ResetInterface
{
    private ?Tenant $tenant = null;

    public function __construct(
        private readonly TenantFactory $factory,
        private readonly ManagerRegistry $registry,
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
        $tenant = $this->manager()
            ->find(Tenant::class, $configured->id);
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
            throw TenantNotSynchronizedException::differs($configured->slug, 'authentication_classes', implode(' ', $tenant->authenticationContextPolicy->names()), implode(' ', $configured->authenticationContextPolicy->names()));
        }

        return $this->tenant = $tenant;
    }

    public function reset(): void
    {
        $this->tenant = null;
    }

    public function onClear(): void
    {
        $this->reset();
    }

    private function manager(): EntityManagerInterface
    {
        $manager = $this->registry->getManagerForClass(Tenant::class);
        if (! $manager instanceof EntityManagerInterface) {
            throw new LogicException('No entity manager maps the tenant.');
        }

        return $manager;
    }
}
