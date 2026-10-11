<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_string;

/**
 * The resources a grant carries (RFC 8707 §2) in one column, as the set writes itself
 * (`ResourceIndicators::toDocument()`): space delimited, a resource indicator carrying no space.
 *
 * An empty column is no set at all and never an empty one, which is why this is a type of its own and not
 * a `StringObjectType`: the absence of resources is a null, exactly as it is for the scopes of a token.
 */
final class ResourceIndicatorsType extends Type
{
    public const string NAME = 'beffroi_resources';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! $value instanceof ResourceIndicators) {
            throw InvalidType::new($value, self::NAME, ['null', ResourceIndicators::class]);
        }

        return $value->toDocument();
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?ResourceIndicators
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }

        try {
            return ResourceIndicators::fromDocument($value);
        } catch (InvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }
}
