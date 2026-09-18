<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Core\Domain\Identity\Address;

/**
 * The OIDC Core §5.1.1 address as one JSON document: an embeddable whose every column is null would
 * hydrate as an object, not as null.
 *
 * @extends JsonObjectType<Address>
 */
final class AddressType extends JsonObjectType
{
    public const string NAME = 'heidi_address';

    protected function encode(object $value): array
    {
        return [
            'formatted' => $value->formatted,
            'street_address' => $value->streetAddress,
            'locality' => $value->locality,
            'region' => $value->region,
            'postal_code' => $value->postalCode,
            'country' => $value->country,
        ];
    }

    protected function decode(array $data): object
    {
        return new Address(
            $this->nullableString($data, 'formatted'),
            $this->nullableString($data, 'street_address'),
            $this->nullableString($data, 'locality'),
            $this->nullableString($data, 'region'),
            $this->nullableString($data, 'postal_code'),
            $this->nullableString($data, 'country'),
        );
    }

    protected function expects(): string
    {
        return Address::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
