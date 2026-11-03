<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\AsksForARecentProofInterface;
use App\Http\AccountAccess;
use App\Http\WhatWasRefused;
use App\Http\PasskeysPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The passkeys of the signed-in user (architecture §5.2): the list, the form that enrols one, the button
 * that revokes one. A browser without a session of the core is told to sign in first; there is no
 * interaction to send it to, the page belongs to no client.
 *
 * **A session alone does not open it** (AsksForARecentProofInterface): a passkey added is a way in
 * added, and the one revoked may be the last way in somebody has, so the proof is asked again here and
 * at every form this page posts.
 */
#[AsController]
final readonly class AccountPasskeysController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_passkeys';

    public function __construct(
        private AccountAccess $account,
        private WhatWasRefused $refusals,
        private PasskeysPage $page,
    ) {
    }

    public function comesBackTo(): string
    {
        return self::ROUTE;
    }

    #[Route('/account/passkeys', name: self::ROUTE, methods: ['GET'])]
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
