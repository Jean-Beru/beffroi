<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;
use LogicException;
use function sprintf;

/**
 * What the Doctrine implementations of the ports share: the registry, from which the manager of the
 * entity class is taken at every call, so that a manager the kernel reset between two requests or two
 * messages is never held. The ports name find() with the identifier of the domain, which
 * EntityRepository::find() cannot narrow to, hence composition and not ServiceEntityRepository.
 *
 * @template T of object
 */
abstract readonly class DoctrineRepository
{
    /**
     * @param class-string<T> $class
     */
    public function __construct(
        private ManagerRegistry $registry,
        private string $class,
    ) {
    }

    protected function manager(): EntityManagerInterface
    {
        $manager = $this->registry->getManagerForClass($this->class);
        if (! $manager instanceof EntityManagerInterface) {
            throw new LogicException(sprintf('No entity manager maps "%s".', $this->class));
        }

        return $manager;
    }

    /**
     * @return EntityRepository<T>
     */
    protected function repository(): EntityRepository
    {
        return $this->manager()
            ->getRepository($this->class);
    }

    protected function queryBuilder(string $alias): QueryBuilder
    {
        return $this->repository()
            ->createQueryBuilder($alias);
    }

    protected function store(object $entity): void
    {
        $manager = $this->manager();
        $manager->persist($entity);
        $manager->flush();
    }
}
