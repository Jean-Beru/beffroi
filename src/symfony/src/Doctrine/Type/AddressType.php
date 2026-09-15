<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Core\Domain\Identity\Address;

/**
 * The postal address of a user as one JSON document with the members of the OIDC Core §5.1.1 address
 * claim. A JSON column rather than an embeddable because an absent address is null on the user, and
 * Doctrine hydrates an embeddable whose every column is null as an object, not as null.
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
