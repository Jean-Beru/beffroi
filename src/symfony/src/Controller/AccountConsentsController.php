<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\ConsentsPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * What the signed-in user has agreed to (architecture §5.2): the clients that may obtain something about
 * them, and the button that takes one back. A browser without a session of the core is told to sign in
 * first; there is no interaction to send it to, the page belongs to no client.
 */
#[AsController]
final readonly class AccountConsentsController
{
    public const string ROUTE = 'heidi_interaction_account_consents';

    public function __construct(
        private AccountAccess $account,
        private ConsentsPage $page,
    ) {
    }

    #[Route('/account/consents', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session->user);
    }
}
