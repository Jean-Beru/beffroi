<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\TwoFactorPage;
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
    public const string ROUTE = 'heidi_interaction_account_two_factor';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private InteractionPages $pages,
        private TwoFactorPage $page,
    ) {
    }

    #[Route('/account/two-factor', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->browser->authenticationSession($request, $this->tenants->provide());
        if ($session === null) {
            return $this->pages->error(Response::HTTP_UNAUTHORIZED, AccountPasskeysController::LOGIN_REQUIRED);
        }

        return $this->page->render($session->user);
    }
}
