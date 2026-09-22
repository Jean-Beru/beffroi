<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\GeoLocation;
use Heidi\Core\Exception\InvalidArgumentException;
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
        yield 'latitude alone' => [null, 45.0, null];
        yield 'longitude alone' => [null, null, 4.0];
        yield 'latitude out of range' => [null, 91.0, 0.0];
        yield 'latitude below range' => [null, -91.0, 0.0];
        yield 'longitude out of range' => [null, 0.0, 181.0];
        yield 'longitude below range' => [null, 0.0, -181.0];
    }
}
