<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\ProfilePage;
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
final readonly class AccountProfileController
{
    public const string ROUTE = 'heidi_interaction_account_profile';

    public function __construct(
        private AccountAccess $account,
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

        return $this->page->render($session->user);
    }
}
