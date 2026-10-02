<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;

/**
 * The badge of the second step of a login (architecture §5.4), the counterpart of PasswordCredentials
 * and PasskeyCredentials: the login the code completed, with what its first step proved, and what the
 * code proved ("otp"), verified by the core before the passport was built.
 */
final readonly class TotpCredentials implements CredentialsInterface
{
    public function __construct(
        public PendingLogin $login,
        public AuthenticationMethod $method,
    ) {
    }

    public function isResolved(): bool
    {
        return true;
    }
}
