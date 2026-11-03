<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine;

use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Exception\RuntimeException;
use Doctrine\ORM\QueryBuilder;
use SortDirection;
use function sprintf;

/**
 * One page of the rows a selection finds (architecture §5.2): how many there are, the page of them that was
 * asked for held inside that number, and the rows of that page.
 *
 * The one place the three steps are written. A repository of this bundle that answers a page of a table of
 * the account hands its selection here and says what to order it by, so that no two of them count and slice
 * in a way of their own, and so that the count is taken of the same rows the page reads.
 *
 * The order is not on the selection that arrives: a count of rows ordered by a column it does not count is
 * not a query PostgreSQL answers, so the order belongs to the reading of the rows and to nothing else. The
 * alias is the selection's own, so a count of something other than what is read is not a mistake that can
 * be made here.
 */
final readonly class PageOfRows
{
    /**
     * @template T of object
     *
     * @param class-string<T> $rows      what the selection reads, which types the page it gives back
     * @param QueryBuilder    $selection the rows to read, their conditions set and their order not
     * @param string          $orderBy   the field the table is read in the order of, with its alias
     *
     * @return Listing<T>
     *
     * @throws RuntimeException when the selection reads no alias, which is a selection of nothing
     */
    public function of(
        string $rows,
        QueryBuilder $selection,
        string $orderBy,
        Pagination $pagination,
        SortDirection $direction = SortDirection::Descending,
    ): Listing {
        $alias = $selection->getRootAliases()[0] ?? throw new RuntimeException(sprintf(
            'A selection of %s to be read in pages names no alias.',
            $rows,
        ));
        $total = (int) (clone $selection)->select(sprintf('COUNT(%s)', $alias))->getQuery()->getSingleScalarResult();
        $page = $pagination->within($total);
        /** @var list<T> $rows */
        $rows = $selection->orderBy($orderBy, $direction)->setFirstResult($page->offset())->setMaxResults($page->size)->getQuery()->getResult();

        return new Listing($rows, $page, $total);
    }
}
