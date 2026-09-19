<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PasskeysPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The passkeys of the signed-in user (architecture §5.2): the list, the form that enrols one, the button
 * that revokes one. A browser without a session of the core is told to sign in first; there is no
 * interaction to send it to, the page belongs to no client.
 */
#[AsController]
final readonly class AccountPasskeysController
{
    public const string ROUTE = 'heidi_interaction_account_passkeys';

    public const string LOGIN_REQUIRED = 'login_required';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private InteractionPages $pages,
        private PasskeysPage $page,
    ) {
    }

    #[Route('/account/passkeys', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->browser->authenticationSession($request, $this->tenants->provide());
        if ($session === null) {
            return $this->pages->error(Response::HTTP_UNAUTHORIZED, self::LOGIN_REQUIRED);
        }

        return $this->page->render($session->user);
    }
}
