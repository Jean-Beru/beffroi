<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use function array_merge;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Credential\TotpCredential;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use LogicException;
use function sprintf;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * What the logins of the firewall prove, as the core names it (RFC 8176 §2), in one place: what a given
 * passport proved, for the session the listener opens, and everything a login here may prove, for the
 * discovery and the step-up (decision 0010). A fourth badge is a reader of proofs added here.
 */
final readonly class PassportProofs implements ProvableMethodsInterface
{
    /**
     * "pwd" for a password, what the flags of the assertion say for a passkey (PasskeyCredential::methods()),
     * what the first step proved and then "otp" for a code (TotpCredentials). A firewall that
     * authenticates another way is refused loudly rather than recorded wrongly.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function methods(Passport $passport): array
    {
        if ($passport->hasBadge(PasswordCredentials::class)) {
            return [AuthenticationMethod::password()];
        }
        $passkey = $passport->getBadge(PasskeyCredentials::class);
        if ($passkey instanceof PasskeyCredentials) {
            return $passkey->assertion->credential->methods($passkey->assertion->authenticatorData);
        }
        $code = $passport->getBadge(TotpCredentials::class);
        if ($code instanceof TotpCredentials) {
            return [...$code->login->methods, $code->method];
        }

        throw new LogicException(sprintf('The firewall authenticated a user of the bundle without a method the bundle knows: no "%s", "%s" nor "%s" badge on the passport.', PasswordCredentials::class, PasskeyCredentials::class, TotpCredentials::class));
    }

    public function provableMethods(): array
    {
        return array_merge([AuthenticationMethod::password()], PasskeyCredential::everyProvableMethod(), TotpCredential::everyProvableMethod());
    }
}
