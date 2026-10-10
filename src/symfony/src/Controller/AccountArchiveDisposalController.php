<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\ArchivePage;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Core\Application\Archive\ArchiveDisposal;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The person who has their file asks this provider to drop it (RGPD articles 15 and 20, issue #453): the
 * row goes before the date it would have gone away on by itself, and the page says they hold none again.
 *
 * There is nothing to name in the request: what is dropped is the last archive of the person who asks
 * (ArchiveDisposal), so no identifier travels and somebody else's file is not reachable from here.
 *
 * It answers with a redirection whether there was a file or not (issue #481), and a person whose file went
 * away under them reads why on the page they come back to.
 */
#[AsController]
final readonly class AccountArchiveDisposalController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_archive_drop';

    public const string CSRF_TOKEN_ID = 'beffroi_archive_drop';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private ArchiveDisposal $disposal,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/archive/drop', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        if (! $this->disposal->droppedBy($session->user, $this->contexts->fromRequest($request))) {
            // the file was taken by the retention, or a second click arrived: the page would say nothing
            // of the difference, and what somebody asked for and did not get is said once (issue #481)
            $this->refusals->keep($request, ArchivePage::NOTHING_TO_DROP);
        }

        return $this->pages->afterTheForm(AccountArchiveController::ROUTE);
    }
}
