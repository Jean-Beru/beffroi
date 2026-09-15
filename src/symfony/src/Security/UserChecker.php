<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The state of the account, checked after the password and not before, as the core does: a disabled
 * account answers exactly like a wrong password to whoever does not know the password, in time as in
 * words. The firewall turns the exception into "bad credentials" for the user; the reason stays in the
 * audit trail (LoginFailureListener).
 */
final readonly class UserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user): void
    {
    }

    public function checkPostAuth(UserInterface $user, ?TokenInterface $token = null): void
    {
        if ($user instanceof SecurityUser && ! $user->enabled) {
            $exception = new DisabledException('User account is disabled.');
            $exception->setUser($user);

            throw $exception;
        }
    }
}
