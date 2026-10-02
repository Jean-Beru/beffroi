<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\QueryBuilder;
use Beffroi\Bundle\Doctrine\EntityManagers;

/**
 * What the Doctrine implementations of the ports share. The manager is asked for at every call, never
 * held; composition rather than ServiceEntityRepository, whose find() the ports cannot narrow.
 *
 * @template T of object
 */
abstract readonly class DoctrineRepository
{
    /**
     * @param class-string<T> $class
     */
    public function __construct(
        private EntityManagers $managers,
        private string $class,
    ) {
    }

    protected function manager(): EntityManagerInterface
    {
        return $this->managers->forClass($this->class);
    }

    /**
     * @return EntityRepository<T>
     */
    protected function repository(): EntityRepository
    {
        return $this->manager()->getRepository($this->class);
    }

    protected function queryBuilder(string $alias): QueryBuilder
    {
        return $this->repository()->createQueryBuilder($alias);
    }

    protected function store(object $entity): void
    {
        $manager = $this->manager();
        $manager->persist($entity);
        $manager->flush();
    }

    /**
     * One flush for a set a single call changed, a consent taken back reaching every grant it covers at
     * once (architecture §4.3).
     *
     * @param list<T> $entities
     */
    protected function storeAll(array $entities): void
    {
        if ($entities === []) {
            return;
        }
        $manager = $this->manager();
        foreach ($entities as $entity) {
            $manager->persist($entity);
        }
        $manager->flush();
    }
}
