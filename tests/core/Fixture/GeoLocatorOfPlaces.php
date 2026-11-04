<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Port\GeoLocatorInterface;

final class GeoLocatorOfPlaces implements GeoLocatorInterface
{
    /**
     * @var list<string>
     */
    public private(set) array $asked = [];

    /**
     * @param array<string, GeoLocation> $places by address
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
