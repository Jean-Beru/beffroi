<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Core\Domain\Credential\VerifiedPasskeyAssertion;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;

/**
 * The badge of a passkey login (architecture §5.4), the counterpart of PasswordCredentials: what the
 * authentication ceremony verified, already resolved, because the signature was checked before the
 * passport was built and nothing of the firewall has to check it again.
 */
final readonly class PasskeyCredentials implements CredentialsInterface
{
    public function __construct(
        public VerifiedPasskeyAssertion $assertion,
    ) {
    }

    public function isResolved(): bool
    {
        return true;
    }
}
