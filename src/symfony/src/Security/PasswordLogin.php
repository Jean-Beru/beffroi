<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Session\AuthenticationMethod;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The form login of the firewall (architecture §5.4): a password, "pwd" (RFC 8176 §2), and nothing else.
 * The code that may follow it is the TOTP login's to declare, and the two together are what the policy
 * of the tenant reads as two factors.
 */
final readonly class PasswordLogin implements ProvingLoginInterface
{
    public function proofs(Passport $passport): ?array
    {
        return $passport->hasBadge(PasswordCredentials::class) ? [AuthenticationMethod::password()] : null;
    }

    public function everyProvableMethod(): array
    {
        return [AuthenticationMethod::password()];
    }
}
