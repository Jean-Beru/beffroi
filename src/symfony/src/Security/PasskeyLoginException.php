<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Throwable;

/**
 * A passkey login the authenticator of the bundle refused, with what the audit trail needs (§3.4): the
 * reason, the method the assertion claimed when the ceremony got that far, the user it named when it
 * named one. The user is told "failed" and nothing else, as with a password.
 */
final class PasskeyLoginException extends AuthenticationException
{
    public function __construct(
        public readonly AuthenticationFailureReason $reason,
        public readonly ?AuthenticationMethod $method = null,
        public readonly ?User $user = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct('Passkey login failed.', 0, $previous);
    }

    public function getMessageKey(): string
    {
        return 'Invalid credentials.';
    }
}
