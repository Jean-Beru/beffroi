<?php

declare(strict_types=1);

namespace App\Security;

use Beffroi\Core\Domain\Credential\TotpCredential;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The second step of a login on the firewall (architecture §5.4): what the first step proved, carried by
 * the badge since the session is opened only now, and "otp" for the code.
 *
 * It dates nothing: the code was dated and announced by the core where it was verified, and so was the
 * password of the first step (PasswordVerification, issue #130).
 */
final readonly class TotpLogin implements ProvingLoginInterface
{
    public function proofs(Passport $passport): ?array
    {
        $badge = $passport->getBadge(TotpCredentials::class);
        if (! $badge instanceof TotpCredentials) {
            return null;
        }

        return [...$badge->login->methods, $badge->method];
    }

    /**
     * A code proves "otp", a backup code as much as a TOTP (TotpCredential::method()); the password it
     * follows is the password login's to declare.
     */
    public function everyProvableMethod(): array
    {
        return [TotpCredential::method()];
    }
}
