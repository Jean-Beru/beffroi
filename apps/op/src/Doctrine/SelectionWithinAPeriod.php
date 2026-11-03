<?php

declare(strict_types=1);

namespace App\Doctrine;

use Beffroi\Core\Domain\Listing\Period;
use DateTimeZone;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\QueryBuilder;

/**
 * What a table of the account is read over, written into the selection that reads it (architecture §5.2):
 * the rows dated inside the stretch of time somebody asked for, and every row when they asked for none.
 *
 * **The narrowing comes before the page** (PageOfRows): the count a control shows is the count of what was
 * asked for, and a reader looking for one afternoon of a journal of a year is not paging through the year.
 *
 * The two ends are days on the clock of the person who typed them (AskedPeriod), where the column holds
 * what the clock of this provider wrote: what is compared is one clock and not two.
 */
final readonly class SelectionWithinAPeriod
{
    /**
     * @param string $column the column that dates a row, with the alias of the selection ("a.occurredAt")
     */
    public static function narrow(QueryBuilder $selection, string $column, ?Period $period): QueryBuilder
    {
        if ($period?->from !== null) {
            $selection->andWhere($column . ' >= :period_from')->setParameter(
                'period_from',
                $period->from->setTimezone(new DateTimeZone('UTC')),
                Types::DATETIME_IMMUTABLE,
            );
        }
        if ($period?->to !== null) {
            $selection->andWhere($column . ' <= :period_to')->setParameter(
                'period_to',
                $period->to->setTimezone(new DateTimeZone('UTC')),
                Types::DATETIME_IMMUTABLE,
            );
        }

        return $selection;
    }
}
