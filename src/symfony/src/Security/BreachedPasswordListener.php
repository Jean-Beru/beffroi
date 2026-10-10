<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Message\CheckThePasswordAgainstTheBreaches;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * The password already posed, looked up after the login that used it (issue #552, architecture §3.4). The
 * step of a password login that costs the login nothing: it takes the digest while the password is in
 * memory and orders the lookup on the lane, so that a password found in a corpus published after it was
 * written is found at all.
 *
 * **It claims one step of the order of a login and writes no second copy of it** (issue #130): the two
 * halves are the two events the firewall already decides a password login on, and both are guarded by the
 * badge of a password, so a passkey login and the code of a second step pass through untouched.
 *
 * **The digest is taken before the hash is verified and the lookup is ordered after.** It has to be taken
 * before, because Symfony's CheckCredentialsListener resolves the badge and the password is gone from it
 * (the PasswordUpgradeBadge it leaves behind erases what it holds on the one read PasswordMigratingListener
 * owes it). And it has to be ordered after, because a password that did not verify is not this user's
 * password: nothing of a wrong guess is sent to anybody, a refused login never reaching LoginSuccessEvent.
 *
 * **A login that holds a password and waits on a second factor is looked up all the same**: the password
 * was proven, which is what this is about, and LoginSuccessEvent is where SecondFactorGate holds the login
 * rather than where it is refused.
 *
 * **A deployment that names no list computes nothing and writes nothing to a queue**, and a credential
 * looked up inside its delay is left alone (PasswordCredential::dueForABreachLookup()): a login does not
 * ask again what was asked last month.
 */
final readonly class BreachedPasswordListener
{
    /**
     * Where the digest the lookup will carry is taken: after the decoy of a user without a password (64),
     * before the hash (0), while the password is still on the badge.
     */
    public const int BEFORE_THE_HASH = 32;

    /**
     * Where the digest waits for the hash to be verified: on the passport of the request and nowhere a
     * second request can read it, so it dies with the one that typed the password.
     */
    public const string DIGEST = 'beffroi_password_digest';

    public function __construct(
        private BreachedPasswordsInterface $breaches,
        private MessageBusInterface $commandBus,
        private ClockInterface $clock,
    ) {
    }

    #[AsEventListener(priority: self::BEFORE_THE_HASH)]
    public function onCheckPassport(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();
        $credentials = self::passwordOf($passport);
        if ($credentials === null || ! $this->breaches->looksUp()) {
            return;
        }
        $user = $passport->getUser();
        $credential = $user instanceof SecurityUser ? $user->passwordCredential() : null;
        if ($credential === null || ! $credential->dueForABreachLookup($this->clock->now())) {
            return;
        }
        $passport->setAttribute(self::DIGEST, PasswordDigest::of($credentials->getPassword()));
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $passport = $event->getPassport();
        $digest = $passport->getAttribute(self::DIGEST);
        $user = $event->getUser();
        if (! $digest instanceof PasswordDigest || ! $user instanceof SecurityUser) {
            return;
        }
        $credential = $user->passwordCredential();
        if ($credential === null) {
            return;
        }
        $this->commandBus->dispatch(new CheckThePasswordAgainstTheBreaches($credential->id, $digest->value));
    }

    /**
     * The badge of a password login, with the password still on it; null for anything else.
     */
    private static function passwordOf(Passport $passport): ?PasswordCredentials
    {
        $badge = $passport->getBadge(PasswordCredentials::class);
        if (! $badge instanceof PasswordCredentials || $badge->isResolved()) {
            return null;
        }

        return $badge->getPassword() === '' ? null : $badge;
    }
}
