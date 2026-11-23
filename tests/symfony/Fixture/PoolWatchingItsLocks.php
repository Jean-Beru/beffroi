<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Lock\LockFactory;

/**
 * A pool that records, at each read and each write of a key, whether another holder could have taken the lock of
 * that key.
 */
final class PoolWatchingItsLocks implements CacheItemPoolInterface
{
    /**
     * @var list<bool> one entry per read and per write, true when the lock of the key was free
     */
    public private(set) array $lockFree = [];

    private readonly ArrayAdapter $pool;

    public function __construct(
        private readonly LockFactory $locks,
    ) {
        $this->pool = new ArrayAdapter();
    }

    public function getItem(string $key): CacheItemInterface
    {
        $this->watch($key);

        return $this->pool->getItem($key);
    }

    /**
     * @param array<string> $keys
     *
     * @return iterable<string, CacheItemInterface>
     */
    public function getItems(array $keys = []): iterable
    {
        return $this->pool->getItems($keys);
    }

    public function hasItem(string $key): bool
    {
        $this->watch($key);

        return $this->pool->hasItem($key);
    }

    public function clear(): bool
    {
        return $this->pool->clear();
    }

    public function deleteItem(string $key): bool
    {
        return $this->pool->deleteItem($key);
    }

    /**
     * @param array<string> $keys
     */
    public function deleteItems(array $keys): bool
    {
        return $this->pool->deleteItems($keys);
    }

    public function save(CacheItemInterface $item): bool
    {
        $this->watch($item->getKey());

        return $this->pool->save($item);
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->pool->saveDeferred($item);
    }

    public function commit(): bool
    {
        return $this->pool->commit();
    }

    private function watch(string $key): void
    {
        $other = $this->locks->createLock($key);
        $free = $other->acquire();
        if ($free) {
            $other->release();
        }
        $this->lockFree[] = $free;
    }
}
