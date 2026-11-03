<?php

declare(strict_types=1);

namespace App\Geo;

use function is_array;
use function is_float;
use function is_int;
use function is_string;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Port\GeoLocatorInterface;
use MaxMind\Db\Reader;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The place of an address, read in the GeoLite2 databases of this deployment (issue #473, docs/09-briques.md):
 * the city edition for the country, the subdivision, the city and the coordinates, the ASN edition for the
 * number of the autonomous system and the organisation that holds it, which are the seven fields of a
 * GeoLocation.
 *
 * **The lookup is local and the address goes nowhere.** It is the reader of the format and not the client
 * of MaxMind: `geoip2/geoip2` adds a web service client that would send this provider's addresses to a
 * third party, and decision 0006 does not leave that as an option. Nothing here holds an HTTP client, which
 * is what makes that true rather than claimed.
 *
 * **It opens the file at every lookup** rather than holding a reader: a worker runs for days, and the
 * database the refresh command replaced under it is the database the next lookup reads. One open per
 * message, on a lane behind a login that has already happened.
 *
 * **Nothing it reads can fail a lookup.** A database that was never downloaded, one that cannot be read,
 * an address no network of it covers and a record that does not say what the edition says it says are all
 * one answer, no place, because what fails is an enrichment and not the act it enriches.
 */
final readonly class GeoLite2GeoLocator implements GeoLocatorInterface
{
    public function __construct(
        private GeoLite2Databases $databases,
        private LoggerInterface $logger,
    ) {
    }

    public function locate(string $ipAddress): ?GeoLocation
    {
        $city = $this->record(GeoLite2Databases::CITY, $ipAddress);
        $network = $this->record(GeoLite2Databases::ASN, $ipAddress);
        if ($city === [] && $network === []) {
            return null;
        }

        return $this->place($city, $network);
    }

    /**
     * @param array<string, mixed> $city
     * @param array<string, mixed> $network
     */
    private function place(array $city, array $network): ?GeoLocation
    {
        $coordinates = self::map($city, 'location');
        try {
            return new GeoLocation(
                self::text(self::map($city, 'country'), 'iso_code'),
                self::name(self::subdivision($city)),
                self::name(self::map($city, 'city')),
                self::number($network, 'autonomous_system_number'),
                self::text($network, 'autonomous_system_organization'),
                self::coordinate($coordinates, 'latitude'),
                self::coordinate($coordinates, 'longitude'),
            );
        } catch (Throwable $exception) {
            // A record of the shape the edition does not describe: the place is lost and the act that
            // carried the address keeps its address, which is what an enrichment is allowed to cost.
            $this->logger->warning('The databases of addresses answered a record this provider cannot read.', [
                'exception' => $exception,
            ]);

            return null;
        }
    }

    /**
     * What the edition says of that address, and nothing at all when it says nothing: this deployment
     * holds no such database, the file cannot be read, or no network of it covers the address.
     *
     * @return array<string, mixed>
     */
    private function record(string $edition, string $ipAddress): array
    {
        $path = $this->databases->path($edition);
        if ($path === null) {
            return [];
        }
        $reader = null;
        try {
            $reader = new Reader($path);

            return self::named($reader->get($ipAddress));
        } catch (Throwable $exception) {
            $this->logger->warning('The database of addresses "{edition}" cannot be read.', [
                'edition' => $edition,
                'exception' => $exception,
            ]);

            return [];
        } finally {
            $reader?->close();
        }
    }

    /**
     * The most specific subdivision the city edition carries, which is the region of a place: a country
     * that nests two of them (a region and its department) says the smaller one last.
     *
     * @param array<string, mixed> $city
     *
     * @return array<string, mixed>
     */
    private static function subdivision(array $city): array
    {
        $subdivisions = $city['subdivisions'] ?? null;
        if (! is_array($subdivisions)) {
            return [];
        }
        $last = [];
        foreach ($subdivisions as $subdivision) {
            if (is_array($subdivision)) {
                $last = self::named($subdivision);
            }
        }

        return $last;
    }

    /**
     * The name of a place, in English: the enrichment runs on a lane, where no visitor and no
     * "Accept-Language" is in sight, and English is the one language every edition carries. What a page
     * does say in the language of its reader is the country, which ICU names from the code beside it.
     *
     * @param array<string, mixed> $place
     */
    private static function name(array $place): ?string
    {
        return self::text(self::map($place, 'names'), 'en');
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed>
     */
    private static function map(array $record, string $key): array
    {
        return self::named($record[$key] ?? null);
    }

    /**
     * A document of the database read by name: what the reader gives back is whatever the record holds,
     * and what this provider takes of it, it takes by the names the edition documents.
     *
     * @return array<string, mixed>
     */
    private static function named(mixed $document): array
    {
        if (! is_array($document)) {
            return [];
        }
        $named = [];
        foreach ($document as $key => $value) {
            $named[(string) $key] = $value;
        }

        return $named;
    }

    /**
     * @param array<string, mixed> $record
     */
    private static function text(array $record, string $key): ?string
    {
        $value = $record[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param array<string, mixed> $record
     */
    private static function number(array $record, string $key): ?int
    {
        $value = $record[$key] ?? null;

        return is_int($value) ? $value : null;
    }

    /**
     * @param array<string, mixed> $record
     */
    private static function coordinate(array $record, string $key): ?float
    {
        $value = $record[$key] ?? null;

        return is_float($value) || is_int($value) ? (float) $value : null;
    }
}
