<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use function is_string;

/**
 * Raw bytes (a credential ID, a COSE key) in a text column as base64url without padding (RFC 4648 §5):
 * readable in a row, indexable, and never a stream, which is what the binary types of DBAL hand back.
 *
 * The alphabet is the core's (Base64Url), which is also what the document a person downloads writes those
 * same bytes in: what a column holds and what an archive says of it are one encoding.
 */
final class BytesType extends Type
{
    public const string NAME = 'beffroi_bytes';

    public static function encode(string $bytes): string
    {
        return Base64Url::encode($bytes);
    }

    /**
     * Null when the text is not base64url.
     */
    public static function decode(string $encoded): ?string
    {
        return Base64Url::decode($encoded);
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }

        return self::encode($value);
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }

        return self::decode($value) ?? throw ValueNotConvertible::new($value, self::NAME, 'The text is not base64url.');
    }
}
