<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Session\AuthenticationProofs;

/**
 * The proofs of a session (architecture §3.2) as a JSON object of method reference to Unix timestamp,
 * the shape of TokenInterface::getAuthenticationProofs() and the proofs' own
 * (`AuthenticationProofs::toTimestamps()`).
 *
 * @extends JsonbObjectType<AuthenticationProofs>
 */
final class AuthenticationProofsType extends JsonbObjectType
{
    public const string NAME = 'beffroi_authentication_proofs';

    protected function encode(object $value): array
    {
        return $value->toTimestamps();
    }

    protected function decode(array $data): object
    {
        return AuthenticationProofs::fromTimestamps($data);
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
