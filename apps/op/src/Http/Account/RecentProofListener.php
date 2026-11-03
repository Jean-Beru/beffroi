<?php

declare(strict_types=1);

namespace App\Http\Account;

use App\Http\AccountAccess;
use App\Http\LoginTarget;
use App\Http\RecentLogin;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * What a page of the account that adds or takes away a way in asks before it is called (architecture
 * §5.2): the proof RecentLogin reads of the session, and the login of the firewall when the newest one is
 * older than the window.
 *
 * **It is here and not in the pages**, so that the rule reaches the GET and the POST of a page by
 * construction: a page says it asks (AsksForARecentProofInterface) and the call is made once, where the
 * kernel is about to call it. A page that said it asks and forgot the call would be the hole this closes.
 *
 * **A browser with no session is left to the page**, which refuses it with the one refusal every page of
 * the account writes (AccountAccess): there is nothing to prove again where nothing was proven.
 *
 * The page the login would come back to is forgotten the moment the proof holds, because it is the page
 * that was waiting for the login that forgets it and not the login that answered (LoginTarget), and the
 * page itself never learns that a browser was sent anywhere. It forgets the page it would have asked for
 * and no other: a login a password was demanded of lands on the page of that password with the page it was
 * going to still waiting (BreachedPasswordDemand), and a page served here is not that page.
 *
 * Every page of this plane is one action in one class with its route on `__invoke()`, so the controller the
 * kernel resolved is the page itself and nothing has to be read of a name. A listener of the controller
 * cannot answer in place of the page, ControllerEvent carrying no response, so the page is replaced by the
 * redirection: the page is not called, and nothing it would have written is written.
 */
#[AsEventListener(event: KernelEvents::CONTROLLER)]
final readonly class RecentProofListener
{
    public function __construct(
        private AccountAccess $account,
        private RecentLogin $recent,
        private LoginTarget $loginTargets,
    ) {
    }

    public function __invoke(ControllerEvent $event): void
    {
        $page = $event->getController();
        if (! $event->isMainRequest() || ! $page instanceof AsksForARecentProofInterface) {
            return;
        }
        $request = $event->getRequest();
        $session = $this->account->signedIn($request);
        if ($session === null) {
            return;
        }
        $login = $this->recent->orSendToLogin($request, $session, $page->comesBackTo());
        if ($login === null) {
            $this->loginTargets->forgetIfItIsWaitingFor($request->getSession(), $page->comesBackTo());

            return;
        }
        $event->setController(static fn (): Response => $login);
    }
}
