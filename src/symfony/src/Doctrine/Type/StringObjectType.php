<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use Heidi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Heidi\Oidc\Exception\InvalidArgumentException as OidcInvalidArgumentException;
use function is_string;

/**
 * A value object that is one validated string, stored as that string. Read back through the constructor
 * of the object, so that a row somebody edited by hand fails at load and not further down.
 *
 * @template T of object
 */
abstract class StringObjectType extends Type
{
    /**
     * @param T $value
     */
    abstract protected function encode(object $value): string;

    /**
     * @throws CoreInvalidArgumentException when the value object refuses the string
     * @throws OidcInvalidArgumentException when the value object refuses the string
     *
     * @return T
     */
    abstract protected function decode(string $value): object;

    /**
     * @return class-string<T>
     */
    abstract protected function expects(): string;

    abstract protected function name(): string;

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getStringTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        $class = $this->expects();
        if (! $value instanceof $class) {
            throw InvalidType::new($value, $this->name(), ['null', $class]);
        }

        return $this->encode($value);
    }

    /**
     * @return T|null
     */
    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?object
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, $this->name(), ['null', 'string']);
        }

        try {
            return $this->decode($value);
        } catch (CoreInvalidArgumentException|OidcInvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, $this->name(), $exception->getMessage(), $exception);
        }
    }
}
