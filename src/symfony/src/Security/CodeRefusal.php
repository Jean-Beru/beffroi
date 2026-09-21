<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Application\Totp\TotpCodeMatcher;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use SensitiveParameter;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * What the code page says of a refused code (issue #133): never why it was refused, which would tell
 * whether the credential exists, but what was typed, which the user already knows. The form has one
 * field and two shapes, the ones TotpCodeMatcher routes on: six digits are a code of the authenticator
 * app, anything else a backup code, and each shape gets the message that names the way out it has. The
 * limit of the attempts is the one reason the page may name, because it is a fact of the request and not
 * of the account, and because trying again is precisely what does not help there.
 *
 * The value is the code the page carries in "data-error" and the last part of the message key, so that
 * a fourth message is a case added with its two entries in the catalogues.
 */
enum CodeRefusal: string
{
    case Code = 'code_refused';

    case BackupCode = 'backup_code_refused';

    case TooManyAttempts = 'too_many_attempts';

    /**
     * What a refusal of the core is told as, on the shape of what was typed; the reason itself goes to
     * the audit trail and no further (AuthenticationFailureReason).
     */
    public static function of(#[SensitiveParameter] string $typed, AuthenticationFailureReason $reason): self
    {
        if ($reason === AuthenticationFailureReason::TooManyAttempts) {
            return self::TooManyAttempts;
        }

        return TotpCodeMatcher::looksLikeCode($typed) ? self::Code : self::BackupCode;
    }

    /**
     * What the page shows for the error the firewall kept, or nothing when it kept none. A refusal of the
     * firewall itself, a form token or an empty field, carries no refusal of the core: the message is the
     * one of a code, whose way out, typing again what the app shows, is the right one there too.
     */
    public static function shown(?AuthenticationException $error): ?self
    {
        if ($error === null) {
            return null;
        }

        return $error instanceof CodeRefusedException ? $error->refusal : self::Code;
    }
}
