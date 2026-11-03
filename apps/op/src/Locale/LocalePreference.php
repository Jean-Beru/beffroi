<?php

declare(strict_types=1);

namespace App\Locale;

use App\Http\BrowserPreferenceInterface;

/**
 * The language a visitor asked for, kept for their browser (issue #448, architecture §5.7): the slot it
 * holds on the cookie of the preferences, and the reading of what that slot carries.
 *
 * It is read on that cookie and never from the URL, which is the rule the language of the pages already
 * follows: a path that carries a locale is a second address for every page, and an authorization request
 * is answered at the address the client registered.
 *
 * What the slot holds is read back against the languages this deployment serves, so that a cookie somebody
 * wrote by hand names a language that has a catalogue or names nothing at all.
 */
final readonly class LocalePreference implements BrowserPreferenceInterface
{
    public const string SLOT = 'locale';

    public function __construct(
        private ServedLocales $served,
    ) {
    }

    public function slot(): string
    {
        return self::SLOT;
    }

    public function read(string $value): ?string
    {
        return $this->served->match([$value]);
    }
}
