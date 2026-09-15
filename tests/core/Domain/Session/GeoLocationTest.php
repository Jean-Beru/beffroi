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
        $location = new GeoLocation(countryCode: 'FR', autonomousSystemNumber: 12322, autonomousSystemOrganization: 'Free SAS', latitude: 45.76, longitude: 4.83);

        static::assertSame('FR', $location->countryCode);
        static::assertNull($location->city);
        static::assertSame(45.76, $location->latitude);
    }

    #[Test]
    public function theEdgesOfTheGlobeAreValidCoordinates(): void
    {
        static::assertSame(-90.0, (new GeoLocation(latitude: -90.0, longitude: -180.0))->latitude);
        static::assertSame(180.0, (new GeoLocation(latitude: 90.0, longitude: 180.0))->longitude);
    }

    #[Test]
    #[DataProvider('provideInvalidLocations')]
    public function itRejectsAnInconsistentLocation(?string $countryCode, ?float $latitude, ?float $longitude): void
    {
        $this->expectException(InvalidArgumentException::class);

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
