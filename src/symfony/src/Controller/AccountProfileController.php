<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Http\ProfilePage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * What this provider holds about the signed-in user (architecture §5.2), for them to read: the account
 * itself and the claims of their record. A browser without a session of the core is told to sign in
 * first; there is no interaction to send it to, the page belongs to no client.
 */
#[AsController]
final readonly class AccountProfileController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_profile';

    public function __construct(
        private AccountAccess $account,
        private WhatWasRefused $refusals,
        private ProfilePage $page,
    ) {
    }

    #[Route('/account/profile', name: self::ROUTE, methods: ['GET'])]
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
