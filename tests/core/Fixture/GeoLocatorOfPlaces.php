<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Port\GeoLocatorInterface;

/**
 * A database of addresses that answers the places it was given, nothing for the addresses it was not, and
 * says which addresses it was asked. What the enrichment of a provenance is tested against (issue #473) is
 * which addresses reach a database and what is written down of the answer, never what a GeoLite2 file holds.
 *
 * It answers the one address the fixtures came from unless a test says otherwise, so that a test which
 * needs an address nothing knows names that address and nothing else.
 */
final class GeoLocatorOfPlaces implements GeoLocatorInterface
{
    /**
     * @var list<string>
     */
    public private(set) array $asked = [];

    /**
     * @param array<string, GeoLocation> $places the place of each address this database covers
     */
    public function __construct(
        private readonly array $places = [
            Fixtures::IP_ADDRESS => new GeoLocation('GB', 'England', 'Oxford', 64_268, 'Example Networks', 51.752, -1.2577),
        ],
    ) {
    }

    public function locate(string $ipAddress): ?GeoLocation
    {
        $this->asked[] = $ipAddress;

        return $this->places[$ipAddress] ?? null;
    }
}
