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

/**
 * Issue #473: the one reading of where an address came from, which both the journal and the sessions go
 * through.
 */
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

    /**
     * A deployment that holds no database answers no place, and that is the whole of what it costs.
     */
    #[Test]
    public function aDeploymentThatLocatesNothingAnswersNoPlace(): void
    {
        // When
        $found = new ProvenancePlace(new NullGeoLocator())->of(Fixtures::context());

        // Then
        static::assertNull($found);
    }

    /**
     * A console and a timed step carry a provenance with no address: there is nothing to ask, and not
     * asking is what this exists for.
     */
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

    /**
     * An enrichment that already ran is an answer already written down: the database is not read again.
     */
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
