<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Exception\KmsUnavailableException;
use Closure;
use ReflectionClass;

/**
 * Rows as a store hands them over before it read them, which is how Doctrine hands over an entity another one
 * points at: an object marked lazy, opened at the first read of a property it does not hold yet, which is when
 * the store reads the row and opens what it seals under the data keys of the tenant (decisions 0011 and 0018).
 * While the KMS does not answer, that read fails with the outage and leaves the object unopened, to be opened by
 * the next read once it answers.
 */
final class UnopenedRows
{
    /**
     * What every read of an unopened row fails with, null while the KMS answers.
     */
    public ?KmsUnavailableException $outage = null;

    /**
     * The row itself made unopened, its identifier ("id", as every entity of the core names it) still readable:
     * whoever holds it holds the same object, which opens with the values it had. What it no longer holds is what
     * PHP lets an object give back, which is everything but its readonly properties already written.
     */
    public function unopen(object $row): void
    {
        $class = new ReflectionClass($row);
        $values = clone $row;
        $class->resetAsLazyGhost($row, $this->opening($class, $values));
        $identifier = $class->getProperty('id');
        $identifier->setRawValueWithoutLazyInitialization($row, $identifier->getValue($values));
    }

    /**
     * A new object standing for the row, unopened, holding nothing but the properties named: what an object built
     * around it reads of it, a session reading the tenant of its person, is readable without opening it.
     *
     * @template T of object
     *
     * @param T $row
     * @param list<string> $readable
     *
     * @return T
     */
    public function unopened(object $row, array $readable = ['id']): object
    {
        $class = new ReflectionClass($row);
        $unopened = $class->newLazyGhost($this->opening($class, $row));
        foreach ($readable as $name) {
            $property = $class->getProperty($name);
            $property->setRawValueWithoutLazyInitialization($unopened, $property->getValue($row));
        }

        return $unopened;
    }

    /**
     * What opens an unopened row with the values of the one it stands for, once the KMS answers.
     *
     * @template T of object
     *
     * @param ReflectionClass<T> $class
     * @param T $values
     *
     * @return Closure(T): void
     */
    private function opening(ReflectionClass $class, object $values): Closure
    {
        return function (object $unopened) use ($class, $values): void {
            if ($this->outage !== null) {
                throw $this->outage;
            }
            foreach ($class->getProperties() as $property) {
                if (! $property->isStatic() && $property->isInitialized($values) && ! $property->isInitialized($unopened)) {
                    $property->setValue($unopened, $property->getValue($values));
                }
            }
        };
    }
}
