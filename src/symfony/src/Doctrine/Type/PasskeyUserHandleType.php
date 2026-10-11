<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Credential\PasskeyUserHandle;

/**
 * The user handle of a passkey (WebAuthn Level 3 §5.4.3), 64 bytes in a text column as the handle writes
 * itself, base64url in the alphabet of the core (`PasskeyUserHandle::toDocument()`).
 *
 * @extends StringObjectType<PasskeyUserHandle>
 */
final class PasskeyUserHandleType extends StringObjectType
{
    public const string NAME = 'beffroi_passkey_user_handle';

    protected function encode(object $value): string
    {
        return $value->toDocument();
    }

    protected function decode(string $value): object
    {
        return PasskeyUserHandle::fromDocument($value);
    }

    protected function expects(): string
    {
        return PasskeyUserHandle::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
