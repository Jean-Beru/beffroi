<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Archive\PersonalArchive;
use DateTimeImmutable;

/**
 * Where the last archive request of a person has got to (issue #453), read in one place: the page of the
 * archive says it in a sentence and the home of the account says it in three words, and the two say the
 * same thing of the same row because they read it here.
 *
 * **The order of the readings is the rule.** A row past its date is nothing whether or not it was ever
 * built, and a row that holds a document is ready whether or not the build took its time, so expiry comes
 * first, then the document, then the delay a build is given (PersonalArchive::BUILT_WITHIN_MINUTES).
 *
 * The five names are what a translation is keyed on, which is why they live beside the pages and not on
 * the entity: the entity says what is true of it, these say what a person is told.
 */
final readonly class ArchiveState
{
    /**
     * This person never asked for one.
     */
    public const string NEVER = 'never';

    /**
     * They asked and the document is not written yet.
     */
    public const string BEING_BUILT = 'being_built';

    /**
     * They asked, the delay a build is given has passed and the document is still not written: nobody is
     * building this one. Asking again opens a new request in its place, and the page says so rather than
     * showing work nobody is doing.
     */
    public const string STALLED = 'stalled';

    public const string READY = 'ready';

    /**
     * It was kept for as long as an archive is kept and is gone, or is about to be: a row past its date is
     * nothing to a reader, whether or not the timed step has come round yet.
     */
    public const string EXPIRED = 'expired';

    public static function of(?PersonalArchive $archive, DateTimeImmutable $now): string
    {
        if ($archive === null) {
            return self::NEVER;
        }
        if ($archive->hasExpired($now)) {
            return self::EXPIRED;
        }
        if ($archive->isReady()) {
            return self::READY;
        }

        return $archive->hasStalled($now) ? self::STALLED : self::BEING_BUILT;
    }
}
