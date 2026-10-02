<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;

/**
 * The decoy hash of the core paid where the firewall refuses a password before any hash (architecture
 * §5.4): Symfony's CheckCredentialsListener loads the user first, so an unknown username leaves the
 * provider as UserNotFoundException before anything is hashed, and a user without a password is refused
 * on the null hash before anything is verified, where a wrong password pays an argon2id verification;
 * the failure is hidden as bad credentials either way, only the time differs. The two are paid here, on
 * CheckPassportEvent, each just before the listener of Symfony that refuses it; an attempt too many is
 * paid by PasswordAttemptListener, which refuses it itself. A form without its token is refused before
 * any of this and pays nothing, as in PasswordAuthenticator it would not have been received.
 */
final readonly class DecoyHashListener
{
    /**
     * After the CSRF token (512), before the user checker (256), the first to load the user.
     */
    public const int BEFORE_THE_USER = 384;

    /**
     * After the attempts (128), before the hash (0), which refuses a user without a password unverified.
     */
    public const int BEFORE_THE_HASH = 64;

    public function __construct(
        private RefusalCost $cost,
    ) {
    }

    #[AsEventListener(priority: self::BEFORE_THE_USER)]
    public function onUnknownUser(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();
        if (! $passport->hasBadge(PasswordCredentials::class)) {
            return;
        }
        try {
            $passport->getUser();
        } catch (UserNotFoundException $exception) {
            $this->cost->pay($passport);

            throw $exception;
        }
    }

    #[AsEventListener(priority: self::BEFORE_THE_HASH)]
    public function onMissingPassword(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();
        if (! $passport->hasBadge(PasswordCredentials::class)) {
            return;
        }
        $user = $passport->getUser();
        if ($user instanceof PasswordAuthenticatedUserInterface && $user->getPassword() === null) {
            $this->cost->pay($passport);
        }
    }
}
