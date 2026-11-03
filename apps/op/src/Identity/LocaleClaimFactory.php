<?php

declare(strict_types=1);

namespace App\Identity;

use App\Locale\KnownLocales;
use Beffroi\Core\Domain\Identity\Claim\Locale;

/**
 * The claim of the language a person reads, built with the languages that exist (issues #476 and #479).
 *
 * A factory and not a claim of its own: what the claim is, how it is read of a person and how their saying
 * it is written are the core's and are not written again here. What the core cannot know is which
 * languages exist in this build of PHP and what each is called in itself, that being ICU read through one
 * object (KnownLocales), so that is what this hands it.
 *
 * It is not the list of languages this deployment serves: that one answers which language a page is in
 * (ServedLocales, architecture §5.7), where this answers what a person says they read.
 */
final readonly class LocaleClaimFactory
{
    public static function of(KnownLocales $known): Locale
    {
        return new Locale($known->all);
    }
}
