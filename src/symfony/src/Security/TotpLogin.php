<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use DateTimeImmutable;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Session\RequestContext;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The second step of a login on the firewall (architecture §5.4): what the first step proved, carried by
 * the badge since the session is opened only now, and "otp" for the code.
 */
final readonly class TotpLogin implements DatesItsCredentialInterface
{
    public function __construct(
        private DatedPasswordCredential $passwords,
    ) {
    }

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

    /**
     * The code was dated by the core, which counted the attempt and spent it; what is left to date is the
     * password of the first step.
     */
    public function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): bool
    {
        if ($this->proofs($passport) === null) {
            return false;
        }
        $this->passwords->of($user, $now);

        return true;
    }
}
