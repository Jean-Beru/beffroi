<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Domain\Tenant\Tenant;
use LogicException;
use Symfony\Contracts\Service\ResetInterface;

/**
 * The tenant of the current request or message: the row Doctrine manages, so that every user, session
 * and token can point at it, checked against the configuration it mirrors. The configuration is
 * provisioning input, TenantSynchronizer writes the row; a row that is missing or disagrees with the
 * configuration refuses to serve rather than serving one of the two.
 *
 * An entity is not a service: the instance is kept for one request or one message and forgotten when the
 * kernel resets its services or when the entity manager is cleared, because the next unit of work will not
 * know it. Nothing that lives longer than a request holds a Tenant, which is why ConfigurationClientRepository
 * takes the tenant at every call.
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

        return $this->tenant = $tenant;
    }

    /**
     * Forgets the instance: called by the kernel between two requests or two messages, and by Doctrine
     * when the entity manager is cleared (the "onClear" event).
     */
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
