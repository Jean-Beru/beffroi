<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The form login of the firewall (architecture §5.4): a password, "pwd" (RFC 8176 §2), and nothing else.
 * The code that may follow it is the TOTP login's to declare, and the two together are what the policy
 * of the tenant reads as two factors.
 *
 * It declares what a passport of that login proved and nothing more: the password was verified by the core
 * before the passport was built, which is where the credential was dated and where every outcome was
 * announced (PasswordVerification, issue #130), so this login dates nothing and announces nothing.
 */
final readonly class PasswordLogin implements OfferedLoginInterface
{
    public function kind(): string
    {
        return 'password';
    }

    public function proofs(Passport $passport): ?array
    {
        return $passport->hasBadge(VerifiedPassword::class) ? [AuthenticationMethod::password()] : null;
    }

    public function everyProvableMethod(): array
    {
        return [AuthenticationMethod::password()];
    }
}
