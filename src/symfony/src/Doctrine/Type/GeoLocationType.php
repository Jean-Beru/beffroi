<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Core\Domain\Session\GeoLocation;

/**
 * What a GeoIP lookup said about an address (architecture §3.5), as one JSON document on the session: the
 * enrichment is asynchronous and optional, and no query of spike 1 filters on it. PostgreSQL reads inside
 * the document when a query needs a country.
 *
 * @extends JsonObjectType<GeoLocation>
 */
final class GeoLocationType extends JsonObjectType
{
    public const string NAME = 'heidi_geo_location';

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
