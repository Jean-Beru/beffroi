<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use function array_map;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use function explode;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function is_array;
use function is_string;

/**
 * A list of scopes in the form of the wire (RFC 6749 §3.3), space delimited.
 */
final class ScopesType extends Type
{
    public const string NAME = 'heidi_scopes';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! is_array($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'list<' . Scope::class . '>']);
        }
        foreach ($value as $scope) {
            if (! $scope instanceof Scope) {
                throw InvalidType::new($value, self::NAME, ['null', 'list<' . Scope::class . '>']);
            }
        }

        return implode(' ', $value);
    }

    /**
     * @return list<Scope>|null
     */
    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?array
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }
        if ($value === '') {
            return [];
        }

        try {
            return array_map(static fn (string $scope): Scope => new Scope($scope), explode(' ', $value));
        } catch (InvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }
}
