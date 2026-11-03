<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Symfony\Component\KeyManagement\BlindIndex\ProjectionInterface;
use Symfony\Component\KeyManagement\BlindIndexInterface;
use Symfony\Component\KeyManagement\DataKeyStoreInterface;
use Symfony\Component\KeyManagement\StoredKeyBlindIndex;

/**
 * One sealed column and the sibling column that holds its blind index (decision 0011).
 *
 * It says what the `BlindIndexed` attribute of the ORM bridge says on an entity, and it says it here
 * because that attribute cannot reach these columns: it would put a class of the bridge inside
 * `Beffroi\Core\Domain`, which is the one thing Deptrac exists to refuse, and it is read off the entity while
 * the mapping of this provider is XML beside it. So the declaration lives with the mapping, and the listener
 * that fills the column is the provider's own (`BlindIndexListener`).
 *
 * The projection is an object of the component and not the name of a class, because what a tag is derived
 * from is a rule and not a setting: a column that needs another projection is a line added here with the
 * class the component ships or one written beside it, and nothing anywhere reads a class name to find out
 * which.
 */
final readonly class BlindIndexedColumn
{
    /**
     * @param class-string $entity the entity both properties are declared on
     * @param string $value the property whose value is indexed
     * @param string $tag the property the tag is written to, which the mapping maps to a column
     * @param ProjectionInterface $projection what of the value is actually indexed, on the way in and on
     *                                        the way out alike
     */
    public function __construct(
        public string $entity,
        public string $value,
        public string $tag,
        private ProjectionInterface $projection,
    ) {
    }

    /**
     * The index of one tenant for this column, over the index key the store holds under that reference. The
     * store is what opens it, so every index over that key costs the one opening it did (decision 0018).
     *
     * **An index is named after the column its tags are written to.** The name is what separates the tags
     * of one index from those of every other index over the same data key, and the key of a tenant serves
     * every column of `BlindIndexedColumns`: unnamed, a username that happens to be an address and that
     * address would share a tag, and whoever reads the two columns would learn which rows of one hold a
     * value of the other. The column is what names it rather than the entity and the property, because a
     * name that changes is a reindexing of every row already written, and a column that is renamed is a
     * migration that rewrites it anyway.
     */
    public function index(DataKeyStoreInterface $store, string $reference): BlindIndexInterface
    {
        return new StoredKeyBlindIndex($store, $reference, $this->tag, $this->projection);
    }
}
