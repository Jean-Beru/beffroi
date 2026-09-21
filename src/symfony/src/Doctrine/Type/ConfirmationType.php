<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Oidc\Domain\Token\Confirmation;

/**
 * What an opaque access token is bound to (RFC 8705 §3), stored as the "cnf" of RFC 7800 §3.1 is
 * written: the members themselves, so that the row says the same thing an "at+jwt" says of the same
 * token, and a confirmation of another kind is another member and not another column.
 *
 * @extends JsonObjectType<Confirmation>
 */
final class ConfirmationType extends JsonObjectType
{
    public const string NAME = 'heidi_confirmation';

    protected function encode(object $value): array
    {
        return [
            Confirmation::CERTIFICATE_THUMBPRINT => $value->certificateThumbprint,
        ];
    }

    protected function decode(array $data): object
    {
        return Confirmation::fromMembers($data);
    }

    protected function expects(): string
    {
        return Confirmation::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
