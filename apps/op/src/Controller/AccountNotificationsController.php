<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\WhatWasRefused;
use App\Http\NotificationsPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The browsers of the signed-in user this provider may push to (architecture §5.2, §5.6): the list, the
 * button that subscribes the browser showing the page, the button that takes one out. A browser without
 * a session of the core is told to sign in first; the page belongs to no client.
 */
#[AsController]
final readonly class AccountNotificationsController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_notifications';

    public function __construct(
        private AccountAccess $account,
        private WhatWasRefused $refusals,
        private NotificationsPage $page,
    ) {
    }

    #[Route('/account/notifications', name: self::ROUTE, methods: ['GET'])]
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
