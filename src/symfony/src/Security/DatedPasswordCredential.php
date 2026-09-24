<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use DateTimeImmutable;
use Heidi\Core\Port\CredentialRepositoryInterface;

/**
 * Dating the password of the user who signed in, for the two logins that prove one: the form login, and
 * the code that completes it, whose first step was a password the core has not dated. A user who holds
 * no password has nothing to date, which is the case of one who signs in with a passkey alone.
 */
final readonly class DatedPasswordCredential
{
    public function __construct(
        private CredentialRepositoryInterface $credentials,
    ) {
    }

    public function of(SecurityUser $user, DateTimeImmutable $now): void
    {
        $credential = $user->passwordCredential();
        if ($credential === null) {
            return;
        }
        $credential->markUsed($now);
        $this->credentials->save($credential);
    }
}
