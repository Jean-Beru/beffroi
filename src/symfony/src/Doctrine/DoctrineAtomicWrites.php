<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine;

use Beffroi\Core\Port\AtomicWritesInterface;
use Closure;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use LogicException;

/**
 * Writes kept all or none in one transaction of the connection the entities of the bundle are written
 * through, the one of the default entity manager, which the bundle prepends its mappings to (§5.3).
 *
 * **The transaction of the connection and not `wrapInTransaction()` of the manager**, as the middleware
 * `doctrine_transaction` of the command bus does it: the manager closes itself when its callback throws,
 * and a refusal raised inside the writes would leave the rest of the request a closed manager. The
 * connection rolls back and the exception goes on; a flush that failed closes the manager on its own, as
 * it does anywhere. A transaction already open around this one, a handler of the command bus, nests, and
 * nothing is kept until the outer one commits.
 */
final readonly class DoctrineAtomicWrites implements AtomicWritesInterface
{
    public function __construct(
        private ManagerRegistry $registry,
    ) {
    }

    public function atomically(Closure $writes): mixed
    {
        $manager = $this->registry->getManager();
        if (! $manager instanceof EntityManagerInterface) {
            throw new LogicException('The default manager of the registry is not an entity manager.');
        }

        return $manager->getConnection()->transactional($writes);
    }
}
