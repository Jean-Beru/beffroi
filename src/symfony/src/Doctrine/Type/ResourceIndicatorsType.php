<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use function explode;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function is_string;

/**
 * The resources a grant carries (RFC 8707 §2), space delimited: a resource indicator is an absolute URI
 * and carries no space, so the set writes itself and reads itself back exactly as a set of scopes does.
 */
final class ResourceIndicatorsType extends Type
{
    public const string NAME = 'beffroi_resources';

    private const string SEPARATOR = ' ';

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

        return implode(self::SEPARATOR, $value->values());
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
            return ResourceIndicators::of(explode(self::SEPARATOR, $value));
        } catch (InvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }
}
