<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\AuthorizationDetailsReaderInterface;
use function is_string;
use function json_encode;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use JsonException;
use LogicException;

/**
 * What a user agreed to beyond the scopes (RFC 9396 §2), stored in the JSON of the wire: the same array a
 * token carries and an introspection renders (§7, §9), read back through the types the deployment is
 * wired with, which are the only things that know what any of it means.
 *
 * A row naming a type the deployment no longer serves fails to convert rather than loading as something
 * else: a detail nobody can describe is a detail nobody can honour.
 */
final class AuthorizationDetailsType extends Type implements NeedsAuthorizationDetailTypesInterface
{
    public const string NAME = 'heidi_authorization_details';

    private static ?AuthorizationDetailsReaderInterface $types = null;

    public static function resolveWith(AuthorizationDetailsReaderInterface $types): void
    {
        self::$types = $types;
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! $value instanceof AuthorizationDetails) {
            throw InvalidType::new($value, self::NAME, ['null', AuthorizationDetails::class]);
        }

        try {
            return json_encode($value->toClaim(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        } catch (JsonException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?AuthorizationDetails
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }
        $types =
            self::$types ?? throw new LogicException('The authorization detail types have not been handed to the DBAL type; the bundle does it when it boots.');

        try {
            return $types->fromJson($value);
        } catch (InvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }
}
