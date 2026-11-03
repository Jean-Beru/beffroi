<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Identity\Address;

/**
 * The OIDC Core §5.1.1 address in one JSON column: an embeddable whose every column is null would
 * hydrate as an object, not as null. What the document holds is the address's own (`Address::toDocument()`).
 *
 * @extends JsonObjectType<Address>
 */
final class AddressType extends JsonObjectType
{
    public const string NAME = 'beffroi_address';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return Address::fromDocument($data);
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
