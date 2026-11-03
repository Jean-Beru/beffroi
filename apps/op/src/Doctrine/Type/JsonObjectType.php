<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidArgumentException as OidcInvalidArgumentException;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use JsonException;

/**
 * A value object stored as a JSON document; a document that does not look like it is a conversion error, never a guess.
 *
 * It keeps the Doctrine half and nothing else: the name the mapping uses, the declaration of the column on
 * each platform, the JSON, and the refusals of DBAL. **What the document looks like is the object's**, in
 * the package that owns it, so that a round trip costs no connection and a second reader of those rows
 * reads them through the same object (issue #603); here, what that object refuses becomes the
 * `ValueNotConvertible` of Doctrine, naming the column it was read out of.
 *
 * @template T of object
 */
abstract class JsonObjectType extends Type
{
    /**
     * What the column holds, as a JSON document. Keyed by names where the value is a record of them, and a
     * list where the value is a set: an empty list of backup codes and a tenant that lets a person change
     * nothing of themselves both write "[]", which is what that value is and not a document with no keys.
     *
     * @param T $value
     *
     * @throws CoreInvalidArgumentException
     * @throws OidcInvalidArgumentException
     *
     * @return array<array-key, mixed>
     */
    abstract protected function encode(object $value): array;

    /**
     * @param array<array-key, mixed> $data
     *
     * @throws CoreInvalidArgumentException
     * @throws OidcInvalidArgumentException
     *
     * @return T
     */
    abstract protected function decode(array $data): object;

    /**
     * @return class-string<T>
     */
    abstract protected function expects(): string;

    abstract protected function name(): string;

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
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

        try {
            return json_encode($this->encode($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        } catch (CoreInvalidArgumentException|OidcInvalidArgumentException|JsonException $exception) {
            throw ValueNotConvertible::new($value, $this->name(), $exception->getMessage(), $exception);
        }
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
            $decoded = json_decode($value, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw ValueNotConvertible::new($value, $this->name(), $exception->getMessage(), $exception);
        }
        if (! is_array($decoded)) {
            throw ValueNotConvertible::new($value, $this->name(), 'A JSON object was expected.');
        }

        try {
            return $this->decode($decoded);
        } catch (CoreInvalidArgumentException|OidcInvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, $this->name(), $exception->getMessage(), $exception);
        }
    }
}
