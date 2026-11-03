<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;

/**
 * What a session had proven at a grant (architecture §4.6), as the three claims every token of the provider
 * writes it as. A record that carries one from the moment it exists embeds it; a record that gains one only
 * when somebody answers it keeps it as a document, because it is absent until then and an embeddable cannot
 * be null.
 *
 * @extends JsonbObjectType<AuthenticationSnapshot>
 */
final class AuthenticationSnapshotType extends JsonbObjectType
{
    public const string NAME = 'beffroi_authentication_snapshot';

    protected function encode(object $value): array
    {
        return $value->toClaims();
    }

    protected function decode(array $data): object
    {
        return AuthenticationSnapshot::fromClaims($data);
    }

    protected function expects(): string
    {
        return AuthenticationSnapshot::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
