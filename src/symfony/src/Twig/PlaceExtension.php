<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use function array_filter;
use function array_values;
use function implode;
use Beffroi\Core\Domain\Session\GeoLocation;
use Locale;
use Symfony\Component\Translation\LocaleSwitcher;
use Twig\Attribute\AsTwigFilter;

/**
 * Where a provenance came from, as the person in front of the page reads it (issue #473): the city, the
 * subdivision and the country of what the enrichment found, from the smallest to the largest, which is
 * the order a reader checks them in. Nothing at all when nothing was found, and the page then says the
 * address alone, as it did before any database was downloaded.
 *
 * **The country is named by ICU and the rest by the database.** A country is a convention of a locale, as
 * a date is, so it is written in the language of the page and nothing of it is a catalogue entry; a city
 * and a subdivision are what the edition carries, which is English, because the enrichment runs on a lane
 * where no reader and no "Accept-Language" is in sight. A code ICU cannot name is written as it stands
 * rather than dropped: a reader who knows it reads it.
 */
final readonly class PlaceExtension
{
    public function __construct(
        private LocaleSwitcher $switcher,
    ) {
    }

    #[AsTwigFilter(name: 'beffroi_place')]
    public function place(?GeoLocation $location): ?string
    {
        if ($location === null) {
            return null;
        }
        $named = array_filter(
            [$location->city, $location->region, $this->country($location->countryCode)],
            static fn (?string $part): bool => $part !== null && $part !== '',
        );
        $written = implode(', ', array_values($named));

        return $written === '' ? null : $written;
    }

    private function country(?string $code): ?string
    {
        if ($code === null) {
            return null;
        }
        $named = Locale::getDisplayRegion('-' . $code, $this->switcher->getLocale());

        return $named === false || $named === '' ? $code : $named;
    }
}
