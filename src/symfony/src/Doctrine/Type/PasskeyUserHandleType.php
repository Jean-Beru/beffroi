<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Core\Domain\Credential\PasskeyUserHandle;
use Heidi\Core\Exception\InvalidArgumentException;

/**
 * The user handle of a passkey (WebAuthn Level 3 §5.4.3), 64 bytes as base64url.
 *
 * @extends StringObjectType<PasskeyUserHandle>
 */
final class PasskeyUserHandleType extends StringObjectType
{
    public const string NAME = 'heidi_passkey_user_handle';

    protected function encode(object $value): string
    {
        return BytesType::encode($value->value);
    }

    protected function decode(string $value): object
    {
        return new PasskeyUserHandle(BytesType::decode($value) ?? throw new InvalidArgumentException('A user handle is base64url.'));
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
