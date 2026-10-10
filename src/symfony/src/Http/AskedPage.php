<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Listing\Pagination;
use function is_numeric;
use function max;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Which page of a table the request in hand asks for (architecture §5.2).
 *
 * One word and one number for every table of the account: a reader who has learned how one of them is paged
 * has learned them all, and a page of this plane that carries a table is paged by this and by nothing of its
 * own. A request that asks for no page asks for the first, and so does one that asks for a page that is not
 * a number: that is a link somebody wrote by hand, and the answer to it is the page they wanted.
 */
final readonly class AskedPage
{
    public const string PARAMETER = 'page';

    /**
     * How many rows a page of a table of the account holds: as many as a person reads at a glance.
     */
    public const int ROWS = 20;

    public function __construct(
        private RequestStack $requests,
    ) {
    }

    public function asked(): Pagination
    {
        $asked = $this->requests->getCurrentRequest()?->query->get(self::PARAMETER);

        return new Pagination(is_numeric($asked) ? max(1, (int) $asked) : 1, self::ROWS);
    }
}
