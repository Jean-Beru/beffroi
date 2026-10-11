<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Session\GeoLocation;

/**
 * What a GeoIP lookup said (architecture §3.5), as one JSON column. What the document holds is the place's
 * own (`GeoLocation::toDocument()`), which is also what the provenance of a request nests.
 *
 * @extends JsonObjectType<GeoLocation>
 */
final class GeoLocationType extends JsonObjectType
{
    public const string NAME = 'beffroi_geo_location';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return GeoLocation::fromDocument($data);
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
