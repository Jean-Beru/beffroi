<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Twig;

use App\Twig\PlaceExtension;
use Beffroi\Core\Domain\Session\GeoLocation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Translation\LocaleSwitcher;

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

    #[Test]
    public function theCountryIsNamedInTheLanguageOfThePage(): void
    {
        // When
        $written = self::place('fr')->place(new GeoLocation('GB', city: 'Oxford'));

        // Then
        static::assertSame('Oxford, Royaume-Uni', $written);
    }

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
