<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\AsksForARecentProofInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Http\TwoFactorPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The second factor of the signed-in user (architecture §5.2): the authenticator app the account holds,
 * with its dates and the backup codes left, the button that removes it, or the button that sets one up.
 * A browser without a session of the core is told to sign in first; there is no interaction to send it
 * to, the page belongs to no client.
 *
 * **A session alone does not open it** (AsksForARecentProofInterface): taking the second factor away is
 * taking a factor away and setting one up is adding a way in, so the proof is asked again here and at
 * every form this page posts.
 */
#[AsController]
final readonly class AccountTwoFactorController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor';

    public function __construct(
        private AccountAccess $account,
        private WhatWasRefused $refusals,
        private TwoFactorPage $page,
    ) {
    }

    public function comesBackTo(): string
    {
        return self::ROUTE;
    }

    #[Route('/account/two-factor', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        // what a form of this page was refused, if one was, shown this once (issue #481)
        return $this->page->render($session->user, $this->refusals->take($request)?->code);
    }
}
