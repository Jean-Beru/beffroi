<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\PersonalData;

use Closure;
use Symfony\Component\KeyManagement\BlindIndex;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;

/**
 * One sealed column and the sibling column that holds its blind index (decision 0011).
 *
 * It says what the `BlindIndexed` attribute of the ORM bridge says on an entity, and it says it here
 * because that attribute cannot reach these columns: it would put a class of the bridge inside
 * `Heidi\Core\Domain`, which is the one thing Deptrac exists to refuse, and it is read off the entity while
 * the mapping of this bundle is XML beside it. So the declaration lives with the mapping, and the listener
 * that fills the column is the bundle's own (`BlindIndexListener`).
 *
 * The projection is a closure rather than the name of a class, because what a tag is derived from is a
 * rule and not a setting: a column that needs another projection is a line added here with the class the
 * component ships or one written beside it, and nothing anywhere reads a class name to find out which.
 */
final readonly class BlindIndexedColumn
{
    /**
     * @param class-string $entity the entity both properties are declared on
     * @param string $value the property whose value is indexed
     * @param string $tag the property the tag is written to, which the mapping maps to a column
     * @param Closure(DataKeyGeneratorInterface, Ciphertext): BlindIndex $projection what of the value is
     *                                                                              actually indexed, on
     *                                                                              the way in and on the
     *                                                                              way out alike
     */
    public function __construct(
        public string $entity,
        public string $value,
        public string $tag,
        private Closure $projection,
    ) {
    }

    /**
     * The index of one tenant for this column, over the index key that tenant's KMS wrapped.
     */
    public function index(DataKeyGeneratorInterface $kms, Ciphertext $wrapped): BlindIndex
    {
        return ($this->projection)($kms, $wrapped);
    }
}
