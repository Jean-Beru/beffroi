<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Session\AuthenticationMethod;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The passkey login of the firewall (architecture §5.4): what the flags of the assertion say
 * (PasskeyCredential::methods(), WebAuthn Level 3 §6.1), read from the badge the authenticator put on
 * the passport after the ceremony.
 */
final readonly class PasskeyLogin implements ProvingLoginInterface
{
    public function proofs(Passport $passport): ?array
    {
        $badge = $passport->getBadge(PasskeyCredentials::class);
        if (! $badge instanceof PasskeyCredentials) {
            return null;
        }

        return $badge->assertion->credential->methods($badge->assertion->authenticatorData);
    }

    /**
     * The flags of an assertion all set at once (decision 0010, architecture §4.8): the key as its backup
     * eligibility says, "swk" for a synced passkey and "hwk" for one bound to its authenticator, "user",
     * the presence §7.2 requires of every assertion, and "mfa", which the authenticator decides at each
     * assertion under userVerification "preferred" and which no single passkey promises ahead
     * (PasskeyCredential::provableMethods()). What this login can reach for a given user is that one,
     * credential by credential; what it can reach at all is this.
     */
    public function everyProvableMethod(): array
    {
        return [
            new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY),
            new AuthenticationMethod(AuthenticationMethod::SOFTWARE_KEY),
            new AuthenticationMethod(AuthenticationMethod::USER_PRESENCE),
            new AuthenticationMethod(AuthenticationMethod::MULTIPLE_FACTORS),
        ];
    }
}
