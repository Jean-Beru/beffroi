<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Locale;

use function array_filter;
use function array_map;
use function array_slice;
use function array_unique;
use function array_values;
use function ctype_alpha;
use function ctype_digit;
use function implode;
use function in_array;
use function preg_split;
use function strlen;
use function strtolower;
use function strtoupper;
use function ucfirst;

/**
 * The languages this deployment has (architecture §5.7): "framework.enabled_locales" with the default
 * locale in front of them, canonical, and the reading of a tag against that list.
 *
 * It is one object and not a rule each caller writes because a tag nobody serves is not a locale of this
 * deployment, whoever asks: a page of the interaction plane reads "ui_locales" and "Accept-Language"
 * against it (InteractionLocale), a message the provider sends a user out of any request of theirs reads
 * a claim against it (UserLocale), and a translator asked for a language that has no catalogue answers in
 * the source language whichever of the two got it wrong.
 */
final readonly class ServedLocales
{
    /**
     * Canonical, the default locale first.
     *
     * @var list<string>
     */
    public array $all;

    public string $default;

    /**
     * @param list<string> $enabledLocales "framework.enabled_locales"
     */
    public function __construct(array $enabledLocales, string $defaultLocale)
    {
        $this->default = self::canonical($defaultLocale);
        $canonical = array_map(self::canonical(...), [$defaultLocale, ...$enabledLocales]);
        $this->all = array_values(array_unique(array_filter($canonical, static fn (string $locale): bool => $locale !== '')));
    }

    /**
     * The first locale of this deployment a tag matches, in the order the tags are given; null when none
     * of them names one.
     *
     * @param list<string> $tags most preferred first
     */
    public function match(array $tags): ?string
    {
        foreach ($tags as $tag) {
            foreach (self::candidates($tag) as $candidate) {
                if (in_array($candidate, $this->all, true)) {
                    return $candidate;
                }
            }
        }

        return null;
    }

    /**
     * "fr_CA", "zh_Hant_TW"; "" for a tag that names no language.
     */
    private static function canonical(string $tag): string
    {
        return self::candidates($tag)[0] ?? '';
    }

    /**
     * RFC 5646 §2.2 read the way Request reads an Accept-Language: language, script and region, most
     * specific first; the rest is ignored.
     *
     * @return list<string>
     */
    private static function candidates(string $tag): array
    {
        $subtags = preg_split('/[-_]/', $tag);
        if ($subtags === false) {
            return [];
        }
        $language = strtolower($subtags[0] ?? '');
        if ($language === '' || ! ctype_alpha($language)) {
            return [];
        }
        $script = null;
        $region = null;
        foreach (array_slice($subtags, 1) as $subtag) {
            $length = strlen($subtag);
            if ($script === null && $region === null && $length === 4 && ctype_alpha($subtag)) {
                $script = ucfirst(strtolower($subtag));
            } elseif ($region === null && ($length === 2 && ctype_alpha($subtag) || $length === 3 && ctype_digit($subtag))) {
                $region = strtoupper($subtag);
            }
        }

        $present = static fn (?string $subtag): bool => $subtag !== null;

        return array_values(array_unique([
            implode('_', array_filter([$language, $script, $region], $present)),
            implode('_', array_filter([$language, $script], $present)),
            implode('_', array_filter([$language, $region], $present)),
            $language,
        ]));
    }
}
