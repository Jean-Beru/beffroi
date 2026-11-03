<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Port\ConfirmationReaderInterface;
use LogicException;

/**
 * What an opaque access token is bound to (RFC 8705 §3), stored as the "cnf" of RFC 7800 §3.1 is
 * written: the members themselves (`ConfirmationInterface::toMembers()`), so that the row says the same
 * thing an "at+jwt" says of the same token, and a confirmation of another kind is another member and not
 * another column.
 *
 * @extends JsonbObjectType<ConfirmationInterface>
 */
final class ConfirmationType extends JsonbObjectType implements NeedsConfirmationReaderInterface
{
    public const string NAME = 'beffroi_confirmation';

    private static ?ConfirmationReaderInterface $confirmations = null;

    public static function resolveWith(ConfirmationReaderInterface $confirmations): void
    {
        self::$confirmations = $confirmations;
    }

    protected function encode(object $value): array
    {
        return $value->toMembers();
    }

    protected function decode(array $data): object
    {
        $confirmations =
            self::$confirmations ?? throw new LogicException('The confirmation kinds have not been handed to the DBAL type; the bundle does it when it boots.');

        return $confirmations->fromMembers($data);
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
