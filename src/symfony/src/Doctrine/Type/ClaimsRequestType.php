<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_string;
use function json_encode;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use JsonException;

/**
 * The "claims" parameter of an authorization request (OIDC Core §5.5), stored in the JSON form the client
 * sent it in and read back by the parser of the module: what the store holds is what the wire carries,
 * and nothing is guessed on the way back.
 */
final class ClaimsRequestType extends Type
{
    public const string NAME = 'heidi_claims_request';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! $value instanceof ClaimsRequest) {
            throw InvalidType::new($value, self::NAME, ['null', ClaimsRequest::class]);
        }

        try {
            return json_encode([
                'userinfo' => self::member($value->userinfo),
                'id_token' => self::member($value->idToken),
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        } catch (JsonException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?ClaimsRequest
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }

        try {
            return ClaimsRequest::fromJson($value);
        } catch (InvalidArgumentException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }

    /**
     * @param array<string, ClaimRequest> $claims
     *
     * @return array<string, array<string, mixed>|null>|object an empty object, so that the member decodes as an object and not as a list
     */
    private static function member(array $claims): array|object
    {
        if ($claims === []) {
            return (object) [];
        }
        $member = [];
        foreach ($claims as $name => $claim) {
            $request = [];
            if ($claim->essential) {
                $request['essential'] = true;
            }
            if ($claim->value !== null) {
                $request['value'] = $claim->value;
            }
            if ($claim->values !== null) {
                $request['values'] = $claim->values;
            }
            $member[$name] = $request === [] ? null : $request;
        }

        return $member;
    }
}
