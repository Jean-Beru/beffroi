<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\ArchivePage;
use Beffroi\Bundle\Http\WhatWasRefused;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The archive of everything this provider holds about the signed-in person (RGPD articles 15 and 20, issue
 * #453): what asking gives them, or where their last request has got to.
 *
 * It reads what the form that asks for a wrapped file was refused, once, out of the session the redirection
 * crossed (issues #481 and #483).
 */
#[AsController]
final readonly class AccountArchiveController
{
    public const string ROUTE = 'beffroi_interaction_account_archive';

    public function __construct(
        private AccountAccess $account,
        private WhatWasRefused $refusals,
        private ArchivePage $page,
    ) {
    }

    #[Route('/account/archive', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session->user, $this->refusals->take($request)?->code);
    }
}
