<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Heidi\Oidc\Domain\Token\Confirmations;

/**
 * What an opaque access token is bound to (RFC 8705 §3), stored as the "cnf" of RFC 7800 §3.1 is
 * written: the members themselves, so that the row says the same thing an "at+jwt" says of the same
 * token, and a confirmation of another kind is another member and not another column.
 *
 * @extends JsonObjectType<ConfirmationInterface>
 */
final class ConfirmationType extends JsonObjectType
{
    public const string NAME = 'heidi_confirmation';

    protected function encode(object $value): array
    {
        return [
            $value->member() => $value->value(),
        ];
    }

    protected function decode(array $data): object
    {
        return Confirmations::fromMembers($data);
    }

    protected function expects(): string
    {
        return ConfirmationInterface::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
