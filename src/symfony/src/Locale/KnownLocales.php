<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Locale;

use function array_key_exists;
use function asort;
use function is_string;
use Locale as IcuLocale;
use ResourceBundle;
use const SORT_STRING;
use function str_replace;

/**
 * The languages a person may say they read (issue #479): the locales ICU has data for, each with its own
 * name in itself.
 *
 * **Not the languages this deployment serves.** "locale" is a claim of OIDC Core §5.1 and not a setting of
 * this provider: it is what the person reads, which a relying party consumes to dress its own pages, so a
 * provider whose own pages are in two languages still holds the claim of somebody who reads a third.
 * Which language a page of this provider is in is another question and another list (ServedLocales).
 *
 * **The locales ICU has data for and no wider.** Past that line nothing here could write a date or a
 * number in the language anyway (`beffroi_moment`, issue #469), so a tag ICU does not know is a tag this
 * provider could hold and never use. The tags are canonical BCP 47, which is the shape the claim is
 * defined in and the shape a browser sends: ICU writes them with underscores.
 *
 * **The name of a language in that language**, which is the only thing recognisable in a list of several
 * hundred: somebody who reads Japanese looks for 日本語 and not for "Japanese". Sorted by that name, so a
 * list reads in the alphabet of whoever is looking rather than in the order ICU keeps its data.
 */
final readonly class KnownLocales
{
    /**
     * @var array<string, string> by the canonical tag, each with its name in itself, sorted by that name
     */
    public array $all;

    public function __construct()
    {
        $names = [];
        // ICU answers false where it has no data at all, which is a build of PHP whose intl carries none
        $locales = ResourceBundle::getLocales('');
        foreach ($locales === false ? [] : $locales as $locale) {
            if (! is_string($locale) || $locale === '') {
                continue;
            }
            $tag = str_replace('_', '-', IcuLocale::canonicalize($locale) ?? $locale);
            if ($tag === '' || array_key_exists($tag, $names)) {
                continue;
            }
            $name = IcuLocale::getDisplayName($locale, $locale);
            $names[$tag] = is_string($name) && $name !== '' ? $name : $tag;
        }
        asort($names, SORT_STRING);
        $this->all = $names;
    }
}
