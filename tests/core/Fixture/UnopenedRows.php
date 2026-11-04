<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Exception\KmsUnavailableException;
use Closure;
use ReflectionClass;

final class UnopenedRows
{
    public ?KmsUnavailableException $outage = null;

    public function unopen(object $row): void
    {
        $class = new ReflectionClass($row);
        $values = clone $row;
        $class->resetAsLazyGhost($row, $this->opening($class, $values));
        $identifier = $class->getProperty('id');
        $identifier->setRawValueWithoutLazyInitialization($row, $identifier->getValue($values));
    }

    /**
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

    public function unopenedSession(AuthenticationSession $session): AuthenticationSession
    {
        return $this->unopened($session, ['id', 'tenant', 'proofs']);
    }

    /**
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
