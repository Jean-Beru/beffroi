<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\AsksForARecentProofInterface;
use App\Http\AccountAccess;
use App\Http\PasswordPage;
use App\Http\WhatWasRefused;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The password of the signed-in person (architecture §5.2): when it was last written, whether a list of
 * compromised passwords has since found it, and the form that replaces it. A browser without a session of
 * the core is told to sign in first; the page belongs to no client.
 *
 * **A session alone does not open it** (AsksForARecentProofInterface): this is the form that replaces what
 * signs somebody in, so a browser whose newest proof is older than the window is sent to the login of the
 * firewall and comes back here with a fresh one. The page says so and asks nothing: the proof is read
 * before the page is called, for the form that posts to it as much as for the page itself.
 *
 * **It is where a login that was asked for a password lands** (BreachedPasswordDemand, issue #579), which
 * the page reads of the session of that browser to say why it is here.
 */
#[AsController]
final readonly class AccountPasswordController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_password';

    public function __construct(
        private AccountAccess $account,
        private WhatWasRefused $refusals,
        private PasswordPage $page,
    ) {
    }

    public function comesBackTo(): string
    {
        return self::ROUTE;
    }

    #[Route('/account/password', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        // what the form was refused, if it was, shown this once (issue #481)
        return $this->page->render($request->getSession(), $session->user, $this->refusals->take($request)?->code);
    }
}
