<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Session\GeoLocation;

/**
 * What a GeoIP lookup said (architecture §3.5), as one JSON document on the session.
 *
 * @extends JsonObjectType<GeoLocation>
 */
final class GeoLocationType extends JsonObjectType
{
    public const string NAME = 'beffroi_geo_location';

    /**
     * The document of a geolocation, and the geolocation of a document, for the type that nests this one
     * rather than holding it in a column of its own (`RequestContextType`): one encoding, named here, so
     * that a nested document and a column of this type cannot drift apart.
     *
     * @return array<string, mixed>|null
     */
    public function document(?GeoLocation $value): ?array
    {
        return $value === null ? null : $this->encode($value);
    }

    /**
     * @param array<array-key, mixed>|null $data
     */
    public function of(?array $data): ?GeoLocation
    {
        $value = $data === null ? null : $this->decode($data);

        return $value instanceof GeoLocation ? $value : null;
    }

    /**
     * Keyed, and said so here: the document of this type is nested in another one (`document()` above),
     * which answers for its own keys.
     *
     * @return array<string, mixed>
     */
    protected function encode(object $value): array
    {
        return [
            'country_code' => $value->countryCode,
            'region' => $value->region,
            'city' => $value->city,
            'asn' => $value->autonomousSystemNumber,
            'as_organization' => $value->autonomousSystemOrganization,
            'latitude' => $value->latitude,
            'longitude' => $value->longitude,
        ];
    }

    protected function decode(array $data): object
    {
        return new GeoLocation(
            $this->nullableString($data, 'country_code'),
            $this->nullableString($data, 'region'),
            $this->nullableString($data, 'city'),
            $this->nullableInt($data, 'asn'),
            $this->nullableString($data, 'as_organization'),
            $this->nullableFloat($data, 'latitude'),
            $this->nullableFloat($data, 'longitude'),
        );
    }

    protected function expects(): string
    {
        return GeoLocation::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
