<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\ArchivePage;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Archive\ArchiveRequest;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A person asks for everything this provider holds about them (RGPD article 15, issue #453).
 *
 * **It builds nothing.** The row is written, the act is announced, and the archive is assembled off this
 * request by whatever carries the events (BuildThePersonalArchiveHandler): nine tables read and one file
 * signed is not work a browser waits for, and the page it comes back to says the file is being built.
 */
#[AsController]
final readonly class AccountArchiveRequestController
{
    public const string ROUTE = 'beffroi_interaction_account_archive_ask';

    public const string CSRF_TOKEN_ID = 'beffroi_archive_ask';

    public function __construct(
        private AccountAccess $account,
        private ArchiveRequest $request,
        private RequestContextFactory $contexts,
        private ArchivePage $page,
    ) {
    }

    #[Route('/account/archive', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $this->request->askedBy($session->user, $this->contexts->fromRequest($request));

        return $this->page->render($session->user);
    }
}
