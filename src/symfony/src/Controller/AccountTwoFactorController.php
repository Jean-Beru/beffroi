<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
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
 */
#[AsController]
final readonly class AccountTwoFactorController
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor';

    public function __construct(
        private AccountAccess $account,
        private TwoFactorPage $page,
    ) {
    }

    #[Route('/account/two-factor', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session->user);
    }
}
