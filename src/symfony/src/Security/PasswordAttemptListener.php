<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Port\PasswordAttemptLimiterInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * The attempts at a password on the firewall, counted by the limiter of the core as PasswordAuthenticator
 * counts them (architecture §3.4, §5.4): once the user of the bundle is loaded and before the hash is
 * verified, after the form token, so that a form without its token is not an attempt on an account; the
 * sixth in a minute refused with the exception of Symfony's own throttling, which the failure listener
 * reads as too_many_attempts and the login page shows as any other failure, after the decoy hash was
 * paid (RefusalCost), so that the refusal costs what a wrong password costs. A password the firewall
 * accepted empties the count, held by the SecondFactorGate or not. An unknown username is loaded by no
 * provider and counted nowhere; a passkey and a code carry no password and are not concerned.
 */
final readonly class PasswordAttemptListener
{
    /**
     * After the CSRF token (512) and the user checker (256), before the hash (0).
     */
    public const int PRIORITY = 128;

    public function __construct(
        private PasswordAttemptLimiterInterface $attempts,
        private RefusalCost $cost,
    ) {
    }

    #[AsEventListener(priority: self::PRIORITY)]
    public function onCheckPassport(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();
        if (! $passport->hasBadge(PasswordCredentials::class)) {
            return;
        }
        $user = $passport->getUser();
        if (! $user instanceof SecurityUser) {
            return;
        }
        if (! $this->attempts->attempt($user->user())) {
            $this->cost->pay($passport);

            throw new TooManyLoginAttemptsAuthenticationException();
        }
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        if (! $event->getPassport()->hasBadge(PasswordCredentials::class) || ! $user instanceof SecurityUser) {
            return;
        }
        $this->attempts->reset($user->user());
    }
}
