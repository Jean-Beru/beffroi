<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Http\PasswordPage;
use Beffroi\Bundle\Http\RecentLogin;
use Beffroi\Bundle\Http\WhatWasRefused;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The password of the signed-in person (architecture §5.2): when it was last written, whether a list of
 * compromised passwords has since found it, and the form that replaces it. A browser without a session of
 * the core is told to sign in first; the page belongs to no client.
 *
 * **A session alone does not open it** (RecentLogin): this is the form that replaces what signs somebody
 * in, so a browser whose newest proof is older than the window is sent to the login of the firewall and
 * comes back here with a fresh one. The redirection it comes back on is the login's, so the page forgets
 * what it had remembered, as every page that asks for a login does.
 */
#[AsController]
final readonly class AccountPasswordController
{
    public const string ROUTE = 'beffroi_interaction_account_password';

    public function __construct(
        private AccountAccess $account,
        private RecentLogin $recent,
        private LoginTarget $loginTargets,
        private WhatWasRefused $refusals,
        private PasswordPage $page,
    ) {
    }

    #[Route('/account/password', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }
        $login = $this->recent->orSendToLogin($request, $session, self::ROUTE);
        if ($login !== null) {
            return $login;
        }
        $this->loginTargets->forget($request->getSession());

        // what the form was refused, if it was, shown this once (issue #481)
        return $this->page->render($session->user, $this->refusals->take($request)?->code);
    }
}
