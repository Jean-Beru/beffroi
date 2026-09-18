<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Domain\Tenant\Tenant;
use LogicException;

/**
 * Writes the row of the configured tenant: created, renamed, or left alone. A changed issuer is refused,
 * every token issued so far names it.
 */
final readonly class TenantSynchronizer
{
    public function __construct(
        private TenantFactory $factory,
        private ManagerRegistry $registry,
    ) {
    }

    /**
     * @throws TenantNotSynchronizedException when the configuration changed the issuer of a stored tenant
     */
    public function synchronize(): Tenant
    {
        $configured = $this->factory->create();
        $manager = $this->manager();
        $tenant = $manager->find(Tenant::class, $configured->id);
        if ($tenant === null) {
            $manager->persist($configured);
            $manager->flush();

            return $configured;
        }
        if (! $tenant->issuer->equals($configured->issuer)) {
            throw TenantNotSynchronizedException::issuerChangeRefused($configured->slug, (string) $tenant->issuer, (string) $configured->issuer);
        }
        if ($tenant->name !== $configured->name) {
            $tenant->rename($configured->name);
            $manager->flush();
        }

        return $tenant;
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
