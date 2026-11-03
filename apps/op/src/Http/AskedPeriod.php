<?php

declare(strict_types=1);

namespace App\Http;

use App\Locale\UserTimeZone;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Listing\Period;
use DateTimeImmutable;
use InvalidArgumentException;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Which stretch of time a table of the account was asked to be read over (architecture §5.2).
 *
 * Two words in the query string, `from` and `to`, for every table that is read over one, as `page` is the
 * one word they are paged by (AskedPage): a reader who has narrowed one table has learned how to narrow
 * the others. A day is read on the clock of the person the page is served to, which is the clock their
 * dates are written on (MomentExtension): a person who asks for yesterday means their yesterday.
 *
 * What is not two days is no stretch of time at all, and the table is read whole: a date that is not a
 * date, and a period that ends before it starts, are a link written by hand, and the page then shows a
 * filter that holds nothing rather than a table that answers nothing.
 */
final readonly class AskedPeriod
{
    public const string FROM = 'from';

    public const string TO = 'to';

    public function __construct(
        private UserTimeZone $zones,
        private RequestStack $requests,
    ) {
    }

    public function asked(?User $reader = null): ?Period
    {
        $request = $this->requests->getCurrentRequest();
        if ($request === null) {
            return null;
        }

        try {
            return Period::ofDays(
                $this->day($request, self::FROM, $reader),
                $this->day($request, self::TO, $reader),
            );
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    private function day(Request $request, string $name, ?User $reader): ?DateTimeImmutable
    {
        $asked = $request->query->get($name);
        if (! is_string($asked) || $asked === '') {
            return null;
        }
        $day = DateTimeImmutable::createFromFormat('!Y-m-d', $asked, $this->zones->of($reader));

        return $day === false ? null : $day;
    }
}
