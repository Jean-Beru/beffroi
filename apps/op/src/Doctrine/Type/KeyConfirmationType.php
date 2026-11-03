<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Oidc\Domain\Token\KeyConfirmation;

/**
 * The key an authorization request reserved its code for (RFC 9449 §10), one thumbprint in one column.
 * The "cnf" of a token is another matter and another type: a token names what it is bound to, whatever
 * the kind, where a request names a key and only a key.
 *
 * @extends StringObjectType<KeyConfirmation>
 */
final class KeyConfirmationType extends StringObjectType
{
    public const string NAME = 'beffroi_key_confirmation';

    /**
     * RFC 7638 §3.1: the base64url of a SHA-256.
     */
    public const int LENGTH = 43;

    protected function encode(object $value): string
    {
        return $value->thumbprint;
    }

    protected function decode(string $value): object
    {
        return new KeyConfirmation($value);
    }

    protected function expects(): string
    {
        return KeyConfirmation::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
