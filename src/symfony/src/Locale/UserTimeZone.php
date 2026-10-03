<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Locale;

use Beffroi\Core\Domain\Identity\User;
use DateTimeZone;
use function date_default_timezone_get;
use function in_array;

/**
 * The clock a date is read on when this provider shows one to a person (issue #469): the zone they told
 * it they are in, when that zone resolves here, and the zone of the deployment otherwise.
 *
 * It sits beside UserLocale because it answers the same kind of question about the same person, and it
 * answers it the same way: "zoneinfo" is a claim of OIDC Core §5.1 and not a setting of this provider, so
 * it is what a person or an upstream provider said, it may be absent, it may name a zone this process
 * cannot resolve, and it is read as a zone rather than taken as one. A claim read against the identifiers
 * of the database is what ServedLocales does with a language tag.
 *
 * The zone of the deployment is the one PHP is configured with ("date.timezone"), because that is where a
 * deployment already says what clock it keeps, and a second place to say it would be a second answer.
 */
final readonly class UserTimeZone
{
    public function of(?User $user): DateTimeZone
    {
        $claimed = $user?->profile->zoneinfo;
        if ($claimed !== null && in_array($claimed, DateTimeZone::listIdentifiers(), true)) {
            return new DateTimeZone($claimed);
        }

        return new DateTimeZone(date_default_timezone_get());
    }
}
