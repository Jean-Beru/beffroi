<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Oidc\Domain\Ciba\BindingMessage;

/**
 * The message shown to a user beside the name of the client that asked (CIBA Core §7.1), stored as the
 * text it is and read back through its constructor: what a row holds is refused at load if it is not what
 * this provider would have accepted, a page being the one place where that text is shown to somebody.
 *
 * @extends StringObjectType<BindingMessage>
 */
final class BindingMessageType extends StringObjectType
{
    public const string NAME = 'beffroi_binding_message';

    protected function encode(object $value): string
    {
        return $value->value;
    }

    protected function decode(string $value): object
    {
        return new BindingMessage($value);
    }

    protected function expects(): string
    {
        return BindingMessage::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
