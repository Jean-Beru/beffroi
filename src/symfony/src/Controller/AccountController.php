<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\AccountHomePage;
use Heidi\Bundle\Http\LoginTarget;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The home of the account (architecture §5.2): where a person who typed the issuer in a browser lands, and
 * the page the other pages of the account hang from. It belongs to no client and to no interaction, as every
 * page of the account does.
 *
 * It is the one page of the account that sends a browser without a session to the login rather than refusing
 * it: there is somewhere to come back to, which is this page itself (LoginTarget). A page that was reached
 * from here refuses what it cannot serve, since a person who followed a link from a page of their account
 * held a session a moment ago.
 */
#[AsController]
final readonly class AccountController
{
    public const string ROUTE = 'heidi_interaction_account';

    public function __construct(
        private AccountAccess $account,
        private LoginTarget $loginTargets,
        private AccountHomePage $page,
    ) {
    }

    #[Route('/account', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->signedIn($request);
        if ($session === null) {
            // remembered so that the login of the firewall brings the browser back here
            return $this->loginTargets->sendToLogin($request->getSession(), self::ROUTE);
        }
        // the page is no longer waiting for a login
        $this->loginTargets->forget($request->getSession());

        return $this->page->render($session);
    }
}
