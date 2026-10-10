<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\PasswordPage;
use Beffroi\Bundle\Http\WhatWasRefused;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The password of the signed-in person (architecture §5.2): when it was last written and the form that
 * replaces it. A browser without a session of the core is told to sign in first; the page belongs to no
 * client.
 */
#[AsController]
final readonly class AccountPasswordController
{
    public const string ROUTE = 'beffroi_interaction_account_password';

    public function __construct(
        private AccountAccess $account,
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

        // what the form was refused, if it was, shown this once (issue #481)
        return $this->page->render($session->user, $this->refusals->take($request)?->code);
    }
}
