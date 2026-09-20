<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Application\Authentication\DecoyHash;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * What a password the firewall refuses before any hash costs: the decoy hash of the core (architecture
 * §3.4), so that an unknown username, a user without a password and a user who tried too often answer in
 * the time of a wrong password, on the firewall as in PasswordAuthenticator. An empty password is the one
 * refusal Symfony's CheckCredentialsListener makes before any hash for a known user; it costs nothing
 * here either, so that the time still tells the two apart in no way. A refusal after the hash, a wrong
 * password or a disabled account, has paid and does not come here: every caller runs before
 * CheckCredentialsListener, while the password is still on the badge.
 */
final readonly class RefusalCost
{
    public function __construct(
        private DecoyHash $decoy,
    ) {
    }

    public function pay(Passport $passport): void
    {
        $credentials = $passport->getBadge(PasswordCredentials::class);
        if (! $credentials instanceof PasswordCredentials) {
            return;
        }
        $password = $credentials->getPassword();
        if ($password === '') {
            return;
        }
        $this->decoy->verify($password);
    }
}
