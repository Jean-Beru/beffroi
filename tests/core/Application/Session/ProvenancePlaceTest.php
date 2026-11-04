<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Session;

use Beffroi\Core\Application\Session\ProvenancePlace;
use Beffroi\Core\Bridge\Null\NullGeoLocator;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\GeoLocatorOfPlaces;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProvenancePlaceTest extends TestCase
{
    #[Test]
    public function itAnswersWhatTheDatabaseSaysOfTheAddress(): void
    {
        // Given
        $locator = new GeoLocatorOfPlaces();

        // When
        $found = new ProvenancePlace($locator)->of(Fixtures::context());

        // Then
        static::assertSame('Oxford', $found?->city);
        static::assertSame([Fixtures::IP_ADDRESS], $locator->asked);
    }

    #[Test]
    public function aDeploymentThatLocatesNothingAnswersNoPlace(): void
    {
        // When
        $found = new ProvenancePlace(new NullGeoLocator())->of(Fixtures::context());

        // Then
        static::assertNull($found);
    }

    #[Test]
    public function aProvenanceWithNoAddressAsksNothing(): void
    {
        // Given
        $locator = new GeoLocatorOfPlaces();

        // When
        $found = new ProvenancePlace($locator)->of(RequestContext::unknown(Fixtures::now()));

        // Then
        static::assertNull($found);
        static::assertSame([], $locator->asked);
    }

    #[Test]
    public function aProvenanceThatAlreadyCarriesAPlaceKeepsItWithoutAsking(): void
    {
        // Given
        $kept = new GeoLocation('FR', city: 'Lyon');
        $locator = new GeoLocatorOfPlaces();

        // When
        $found = new ProvenancePlace($locator)->of(Fixtures::context()->withLocation($kept));

        // Then
        static::assertSame($kept, $found);
        static::assertSame([], $locator->asked);
    }
}
