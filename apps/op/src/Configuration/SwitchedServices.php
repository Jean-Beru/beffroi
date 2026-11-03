<?php

declare(strict_types=1);

namespace App\Configuration;

use Generator;
use IteratorAggregate;

/**
 * The services a tag wires, then those a role of the deployment brings, while the role is on (decision 0030): the tag
 * is known when the container is compiled, and the role is read when the container builds the list (RoleSwitch). A
 * list built while the role is off is the list of a deployment that never declared it: the logins of the firewall
 * without the one an upstream identity provider proves, the algorithms of a family without the key of the role, the
 * channels of the lane without web push.
 *
 * @template T of object
 *
 * @implements IteratorAggregate<int, T>
 */
final readonly class SwitchedServices implements IteratorAggregate
{
    /**
     * @var iterable<T>
     */
    private iterable $brought;

    /**
     * @param iterable<T> $wired what the tag wires, in the order it wires them
     * @param iterable<T> $brought what the role brings, after them: an iterator the container builds lazily, so that
     *                             the list builds nothing of it while the role is off
     */
    public function __construct(
        private iterable $wired,
        RoleSwitch $role,
        iterable $brought,
    ) {
        $this->brought = $role->on ? $brought : [];
    }

    /**
     * @return Generator<int, T>
     */
    public function getIterator(): Generator
    {
        foreach ($this->wired as $service) {
            yield $service;
        }
        foreach ($this->brought as $service) {
            yield $service;
        }
    }
}
