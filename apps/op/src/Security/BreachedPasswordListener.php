<?php

declare(strict_types=1);

namespace App\Security;

use App\Message\CheckThePasswordAgainstTheBreaches;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * The password already posed, looked up after the login that used it (issue #552, architecture §3.4). The
 * step of a password login that costs the login nothing: it takes the digest while the password is in
 * memory and orders the lookup on the lane, so that a password found in a corpus published after it was
 * written is found at all.
 *
 * **It claims one step of the order of a login and writes no second copy of it** (issue #130): it is read
 * on the one event a login of this firewall succeeds on, and it is guarded by the badge of the form login,
 * so a passkey login and the code of a second step pass through untouched.
 *
 * **It is ordered after the password was accepted and never before**, because a password that did not
 * verify is not this user's password: nothing of a wrong guess is sent to anybody, a refused login never
 * reaching LoginSuccessEvent. The password is still on the badge there, the firewall verifying no hash of
 * its own any more (issue #130), where the badge of Symfony had erased it by then.
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
    public function __construct(
        private BreachedPasswordsInterface $breaches,
        private MessageBusInterface $commandBus,
        private ClockInterface $clock,
    ) {
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $passport = $event->getPassport();
        $badge = $passport->getBadge(VerifiedPassword::class);
        $user = $event->getUser();
        if (! $badge instanceof VerifiedPassword || ! $user instanceof SecurityUser || ! $this->breaches->looksUp()) {
            return;
        }
        $credential = $user->passwordCredential();
        if ($credential === null || ! $credential->dueForABreachLookup($this->clock->now())) {
            return;
        }
        $this->commandBus->dispatch(new CheckThePasswordAgainstTheBreaches($credential->id, PasswordDigest::of($badge->password)->value));
    }
}
