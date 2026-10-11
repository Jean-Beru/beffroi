<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * The password the firewall accepted, announced as PasswordAuthenticator announces the one it verifies
 * itself (issue #571, architecture §5.4): on the firewall the hash is verified by Symfony's own form login
 * and not by the use case of the core, so the act of a password is written here or nowhere.
 *
 * It is announced whether the SecondFactorGate holds the login or not, for the same reason the attempts
 * are emptied there (PasswordAttemptListener): the password was accepted, and the code that may follow is
 * another proof and another act. A passkey and a code carry no password and are not concerned; a user who
 * holds no password credential has nothing that was accepted.
 */
final readonly class AcceptedPasswordListener
{
    public function __construct(
        private RequestContextFactory $contexts,
        private EventDispatcherInterface $events,
    ) {
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        if (! $event->getPassport()->hasBadge(PasswordCredentials::class) || ! $user instanceof SecurityUser) {
            return;
        }
        $credential = $user->passwordCredential();
        if ($credential === null) {
            return;
        }
        $context = $this->contexts->fromRequest($event->getRequest());
        $this->events->dispatch(new PasswordUsed($credential, $context->receivedAt, $context));
    }
}
