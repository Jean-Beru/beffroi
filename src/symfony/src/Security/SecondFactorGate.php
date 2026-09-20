<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use DateTimeImmutable;
use Heidi\Bundle\Controller\LoginCodeController;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PendingLoginStore;
use Heidi\Core\Application\Authentication\SecondFactorRequirement;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Where a password login stops being a login (architecture §3.2, §5.4): for a user who holds an active
 * second factor (SecondFactorRequirement of the core), the password the firewall verified is held as a
 * PendingLogin in the HTTP session, the token the firewall just set is dropped so that nothing is granted
 * on a first step, and the browser is sent to the code page instead of the login page. A passkey login is
 * a first factor by itself and passes; so does the second step, whose passport carries no password.
 */
final readonly class SecondFactorGate
{
    public function __construct(
        private SecondFactorRequirement $requirement,
        private PendingLoginStore $pendingLogins,
        private TokenStorageInterface $tokens,
        private InteractionPages $pages,
    ) {
    }

    /**
     * Whether the login was held; the caller then opens no session and binds nothing.
     *
     * @param non-empty-list<AuthenticationMethod> $methods what the passport proved
     */
    public function holds(LoginSuccessEvent $event, SecurityUser $user, array $methods, DateTimeImmutable $now): bool
    {
        if (! $event->getPassport()->hasBadge(PasswordCredentials::class) || ! $this->requirement->requiredFor($user->user())) {
            return false;
        }
        $request = $event->getRequest();
        $this->pendingLogins->hold($request->getSession(), PendingLogin::provenAt($user->id, $methods, $now));
        $this->tokens->setToken(null);
        $event->setResponse($this->pages->redirectToPage(LoginCodeController::ROUTE, $request));

        return true;
    }
}
