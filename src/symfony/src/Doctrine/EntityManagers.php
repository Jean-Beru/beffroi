<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\ObjectManager;
use LogicException;
use function sprintf;

/**
 * The entity manager that maps a class, asked of the registry at every call and never held: a manager
 * closed by a failed flush is replaced in the registry, and whoever kept one would keep the closed one.
 *
 * A registry that answers with something else, or with nothing, is a mapping the bundle was installed
 * without; it is a fault of the integration and never of a request, so it reads the same wherever it is
 * found and is written here alone.
 */
final readonly class EntityManagers
{
    public function __construct(
        private ManagerRegistry $registry,
    ) {
    }

    /**
     * @param class-string $class
     *
     * @throws LogicException when no entity manager maps the class
     */
    public function forClass(string $class): EntityManagerInterface
    {
        $manager = $this->registry->getManagerForClass($class);
        if (! $manager instanceof EntityManagerInterface) {
            throw new LogicException(sprintf('No entity manager maps "%s".', $class));
        }

        return $manager;
    }

    /**
     * Every manager of the deployment, for a caller that asks what is mapped rather than where one class
     * is mapped: which kinds of credential exist is read from the mapping and from nothing else.
     *
     * @return array<string, ObjectManager>
     */
    public function all(): array
    {
        return $this->registry->getManagers();
    }
}
