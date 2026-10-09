<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Twig;

use Beffroi\Bundle\Twig\PlaceExtension;
use Beffroi\Core\Domain\Session\GeoLocation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Translation\LocaleSwitcher;

/**
 * Issue #473: where a provenance came from, as the person in front of the page reads it.
 *
 * What ICU writes for a language is ICU's and changes with its version, so what is asserted here is what
 * the provider decides: which fields, in which order, and in whose language the country is named.
 */
final class PlaceTest extends TestCase
{
    #[Test]
    public function aPlaceIsWrittenFromTheSmallestToTheLargest(): void
    {
        // When
        $written = self::place('en')->place(new GeoLocation('GB', 'England', 'Oxford'));

        // Then
        static::assertSame('Oxford, England, United Kingdom', $written);
    }

    /**
     * A country is a convention of a locale, as a date is: it is named in the language of the page and
     * nothing of it is a catalogue entry.
     */
    #[Test]
    public function theCountryIsNamedInTheLanguageOfThePage(): void
    {
        // When
        $written = self::place('fr')->place(new GeoLocation('GB', city: 'Oxford'));

        // Then
        static::assertSame('Oxford, Royaume-Uni', $written);
    }

    /**
     * A page says the address alone where no database answered, which is every page of a deployment that
     * holds none.
     */
    #[Test]
    #[DataProvider('provideNothingToSay')]
    public function aProvenanceWithNoPlaceIsWrittenAsNothing(?GeoLocation $location): void
    {
        // When / Then
        static::assertNull(self::place('en')->place($location));
    }

    /**
     * @return iterable<string, array{?GeoLocation}>
     */
    public static function provideNothingToSay(): iterable
    {
        yield 'no enrichment ran' => [null];
        yield 'a place of the network alone' => [new GeoLocation(autonomousSystemNumber: 64_268, autonomousSystemOrganization: 'Example Networks')];
    }

    private static function place(string $locale): PlaceExtension
    {
        $switcher = new LocaleSwitcher($locale, []);

        return new PlaceExtension($switcher);
    }
}
