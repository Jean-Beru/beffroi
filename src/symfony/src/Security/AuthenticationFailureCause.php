<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Throwable;

/**
 * What the firewall refused a login for, read from the chain of causes rather than from the exception
 * it wrapped it in: Symfony reports a refusal under the exception of the authenticator, and what
 * happened is behind it. The reasons named here are the ones every login shares, so every login reads
 * them here and names beside them only what is its own.
 */
final readonly class AuthenticationFailureCause
{
    public static function of(AuthenticationException $exception): ?AuthenticationFailureReason
    {
        for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
            if ($cause instanceof UserNotFoundException) {
                return AuthenticationFailureReason::UnknownUser;
            }
            if ($cause instanceof DisabledException) {
                return AuthenticationFailureReason::DisabledUser;
            }
            if ($cause instanceof TooManyLoginAttemptsAuthenticationException) {
                return AuthenticationFailureReason::TooManyAttempts;
            }
        }

        return null;
    }
}
