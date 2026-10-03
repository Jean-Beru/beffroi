<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Identity;

use Beffroi\Bundle\Locale\ServedLocales;
use Beffroi\Core\Domain\Identity\Claim\Locale;

/**
 * The claim of the language a person reads, built with the languages this deployment serves (issue #476).
 *
 * A factory and not a claim of its own: what the claim is, how it is read of a person and how their saying
 * it is written are the core's and are not written again here. What the core cannot know is which
 * languages are served, that being `framework.enabled_locales` read through one object (ServedLocales,
 * architecture §5.7), so that is what this hands it.
 */
final readonly class LocaleClaimFactory
{
    public static function of(ServedLocales $served): Locale
    {
        return new Locale($served->all);
    }
}
