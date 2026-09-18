<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use DateTimeImmutable;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use function is_int;
use function is_string;

/**
 * The proofs of a session (architecture §3.2) as a JSON object of method reference to Unix timestamp,
 * the shape of TokenInterface::getAuthenticationProofs().
 *
 * @extends JsonObjectType<AuthenticationProofs>
 */
final class AuthenticationProofsType extends JsonObjectType
{
    public const string NAME = 'heidi_authentication_proofs';

    protected function encode(object $value): array
    {
        return $value->toTimestamps();
    }

    protected function decode(array $data): object
    {
        $entries = [];
        foreach ($data as $method => $timestamp) {
            if (! is_string($method) || ! is_int($timestamp)) {
                throw ValueNotConvertible::new($data, self::NAME, 'Authentication proofs map a method reference to a Unix timestamp.');
            }
            $entries[$method] = new DateTimeImmutable('@' . $timestamp);
        }

        return new AuthenticationProofs($entries);
    }

    protected function expects(): string
    {
        return AuthenticationProofs::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
