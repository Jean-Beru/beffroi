<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class GeoLocationTest extends TestCase
{
    #[Test]
    public function itAcceptsAPartialLocation(): void
    {
        // When
        $location = new GeoLocation(
            countryCode: 'FR',
            autonomousSystemNumber: 12322,
            autonomousSystemOrganization: 'Free SAS',
            latitude: 45.76,
            longitude: 4.83,
        );

        // Then
        static::assertSame('FR', $location->countryCode);
        static::assertNull($location->city);
        static::assertSame(45.76, $location->latitude);
    }

    #[Test]
    #[DataProvider('provideEdgesOfTheGlobe')]
    public function theEdgesOfTheGlobeAreValidCoordinates(float $latitude, float $longitude): void
    {
        // When
        $location = new GeoLocation(latitude: $latitude, longitude: $longitude);

        // Then
        static::assertSame($latitude, $location->latitude);
        static::assertSame($longitude, $location->longitude);
    }

    /**
     * @return iterable<string, array{float, float}>
     */
    public static function provideEdgesOfTheGlobe(): iterable
    {
        yield 'south west' => [-90.0, -180.0];
        yield 'north east' => [90.0, 180.0];
    }

    #[Test]
    #[DataProvider('provideInvalidLocations')]
    public function itRejectsAnInconsistentLocation(?string $countryCode, ?float $latitude, ?float $longitude): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new GeoLocation(countryCode: $countryCode, latitude: $latitude, longitude: $longitude);
    }

    /**
     * @return iterable<string, array{?string, ?float, ?float}>
     */
    public static function provideInvalidLocations(): iterable
    {
        yield 'lowercase country' => ['fr', null, null];
        yield 'three letter country' => ['FRA', null, null];
        yield 'a line feed behind a country that would pass' => ["FR\n", null, null];
        yield 'latitude alone' => [null, 45.0, null];
        yield 'longitude alone' => [null, null, 4.0];
        yield 'latitude out of range' => [null, 91.0, 0.0];
        yield 'latitude below range' => [null, -91.0, 0.0];
        yield 'longitude out of range' => [null, 0.0, 181.0];
        yield 'longitude below range' => [null, 0.0, -181.0];
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsItAs(GeoLocation $location, array $document): void
    {
        // When / Then
        static::assertSame($document, $location->toDocument());
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(GeoLocation $location, array $document): void
    {
        // When / Then
        static::assertEquals($location, GeoLocation::fromDocument($document));
    }

    /**
     * @return iterable<string, array{GeoLocation, array<string, mixed>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a place' => [
            new GeoLocation('FR', 'Île-de-France', 'Paris', 3215, 'Orange S.A.', 48.8566, 2.3522),
            [
                'country_code' => 'FR',
                'region' => 'Île-de-France',
                'city' => 'Paris',
                'asn' => 3215,
                'as_organization' => 'Orange S.A.',
                'latitude' => 48.8566,
                'longitude' => 2.3522,
            ],
        ];
        yield 'a lookup that said nothing' => [
            new GeoLocation(),
            [
                'country_code' => null,
                'region' => null,
                'city' => null,
                'asn' => null,
                'as_organization' => null,
                'latitude' => null,
                'longitude' => null,
            ],
        ];
    }

    #[Test]
    public function aWholeCoordinateIsReadAsANumber(): void
    {
        // When
        $location = GeoLocation::fromDocument([
            'latitude' => 48,
            'longitude' => 2,
        ]);

        // Then
        static::assertSame(48.0, $location->latitude);
        static::assertSame(2.0, $location->longitude);
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotAPlace')]
    public function aDocumentThatIsNotAPlaceIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        GeoLocation::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotAPlace(): iterable
    {
        yield 'a numeric city' => [
            [
                'city' => 75,
            ],
            'The member "city" must be a string or absent.',
        ];
        yield 'a string ASN' => [
            [
                'asn' => '3215',
            ],
            'The member "asn" must be an integer or absent.',
        ];
        yield 'a string latitude' => [
            [
                'latitude' => '48.8',
                'longitude' => 2.3,
            ],
            'The member "latitude" must be a number or absent.',
        ];
        yield 'a country code the object refuses' => [
            [
                'country_code' => 'France',
            ],
            'The country code "France" must be two uppercase letters (ISO 3166-1 alpha-2).',
        ];
    }
}
