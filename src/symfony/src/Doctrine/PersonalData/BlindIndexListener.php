<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;
use Beffroi\Core\Exception\LogicException;
use function get_debug_type;
use function is_string;
use ReflectionProperty;
use function sprintf;
use Stringable;

/**
 * Writes the blind index of a sealed column in the same statement as the column itself (decision 0011).
 *
 * This is the bundle's own, where an application would carry the `BlindIndexed` attribute of the ORM
 * bridge: that attribute is read off the entity, and the entities of this provider live in the pure-PHP
 * core, which no class of a Doctrine bridge may reach (Deptrac), while their mapping is XML beside this
 * file. So what the attribute would say is said by `BlindIndexedColumns`, and this listener is what reads
 * it.
 *
 * It runs on `onFlush` and not on `prePersist`, for the reason the bridge gives: `prePersist` fires when
 * `persist()` is called, so a use case that persists a user and fills it afterwards would have written an
 * empty tag and lost the row for every search. `onFlush` sees the values the INSERT is about to carry,
 * whatever order the caller did things in, and an insert and an update then take the same path.
 *
 * A tag is derived on every flush of an entity that carries one and not only when the value changed: it
 * costs a keyed digest over a key already in memory, and a row whose tag was written before an index
 * existed repairs itself the next time it is saved. The change set is only recomputed when the tag it
 * holds actually differs.
 *
 * **What it does not cover**, each case leaving a tag that does not match its value. It covers the write
 * path of the ORM only, so a row inserted through DBAL or changed by a bulk `UPDATE` keeps the tag it had,
 * which is worse than an empty one: the search then returns the row that used to hold the value. And it
 * covers the entities `BlindIndexedColumns` names, so a column that starts being searched is a line added
 * there and not a call added to a use case.
 */
final class BlindIndexListener
{
    /**
     * @var array<class-string, list<array{ReflectionProperty, ReflectionProperty, BlindIndexedColumn}>> the
     *      reflection resolved once per class, a flush walking every entity it holds and most of them
     *      carrying no index at all
     */
    private array $resolved = [];

    public function __construct(
        private readonly TenantBlindIndexes $indexes,
    ) {
    }

    public function onFlush(OnFlushEventArgs $event): void
    {
        $manager = $event->getObjectManager();
        $unitOfWork = $manager->getUnitOfWork();

        foreach ([$unitOfWork->getScheduledEntityInsertions(), $unitOfWork->getScheduledEntityUpdates()] as $entities) {
            foreach ($entities as $entity) {
                $metadata = $manager->getClassMetadata($entity::class);

                if ($this->fill($entity, $metadata)) {
                    $unitOfWork->recomputeSingleEntityChangeSet($metadata, $entity);
                }
            }
        }
    }

    /**
     * @param ClassMetadata<object> $metadata
     *
     * @return bool whether a tag was written, and the change set therefore has to be recomputed
     */
    private function fill(object $entity, ClassMetadata $metadata): bool
    {
        $written = false;

        foreach ($this->properties($metadata->getName()) as [$source, $target, $column]) {
            if (! $source->isInitialized($entity)) {
                continue;
            }

            $tag = $this->tag($source->getValue($entity), $column, $entity::class);

            if (! $target->isInitialized($entity) || $target->getValue($entity) !== $tag) {
                $target->setValue($entity, $tag);
                $written = true;
            }
        }

        return $written;
    }

    /**
     * @throws LogicException if the property holds something a keyed digest cannot be taken of
     */
    private function tag(mixed $value, BlindIndexedColumn $column, string $class): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value) && ! $value instanceof Stringable) {
            throw new LogicException(sprintf(
                'The property "%s::$%s" holds a value of type "%s", which no blind index can be derived from: a tag is a keyed digest of a string.',
                $class,
                $column->value,
                get_debug_type($value),
            ));
        }

        return $this->indexes->of($column)->of((string) $value);
    }

    /**
     * @param class-string $class
     *
     * @return list<array{ReflectionProperty, ReflectionProperty, BlindIndexedColumn}>
     *
     * @throws LogicException if a value that may be absent is indexed into a column that refuses null
     */
    private function properties(string $class): array
    {
        if (isset($this->resolved[$class])) {
            return $this->resolved[$class];
        }

        $resolved = [];
        foreach (BlindIndexedColumns::byEntity()[$class] ?? [] as $column) {
            $source = new ReflectionProperty($class, $column->value);
            $target = new ReflectionProperty($class, $column->tag);

            if (($source->getType()?->allowsNull() ?? true) && ! ($target->getType()?->allowsNull() ?? true)) {
                throw new LogicException(sprintf(
                    'The property "%s::$%s" may be absent, but "%s::$%s", which indexes it, refuses null: declare it nullable, or a user who gave no value could not be saved at all.',
                    $class,
                    $column->value,
                    $class,
                    $column->tag,
                ));
            }

            $resolved[] = [$source, $target, $column];
        }

        return $this->resolved[$class] = $resolved;
    }
}
