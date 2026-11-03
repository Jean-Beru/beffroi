<?php

declare(strict_types=1);

namespace App\Security;

use SensitiveParameter;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;

/**
 * The badge of the form login (architecture §5.4), in the place of Symfony's PasswordCredentials and the
 * counterpart of PasskeyCredentials: the password the core verified, already resolved, because the hash
 * was checked before the passport was built and nothing of the firewall checks one any more (issue #130).
 *
 * **It carries the password, and one thing reads it**: the lookup of the password in a list of compromised
 * ones, which takes its digest once the login has succeeded (BreachedPasswordListener, issue #552). It
 * lives as long as the request that typed it, as it did on the badge of Symfony, and it reaches no session,
 * no queue and no event: what travels is a digest of it or nothing.
 */
final readonly class VerifiedPassword implements CredentialsInterface
{
    public function __construct(
        #[SensitiveParameter]
        public string $password,
    ) {
    }

    public function isResolved(): bool
    {
        return true;
    }
}
