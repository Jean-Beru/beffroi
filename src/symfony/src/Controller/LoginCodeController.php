<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PendingLoginStore;
use Heidi\Bundle\Http\RequestContextFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * The code page of an interaction (architecture §5.2, §5.4), shown to a browser whose password login is
 * held until a code: the code of the authenticator app, or a backup code, in one field. The POST is the
 * check path of the TOTP authenticator of the firewall, which sends the browser back here on a refusal,
 * one flat message whatever the reason (decision 0006), or to the login page on a success, which resumes
 * the interaction. Without a login pending, or once it expired, the password is typed again.
 */
#[AsController]
final readonly class LoginCodeController
{
    public const string ROUTE = 'heidi_interaction_login_code';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private PendingLoginStore $pendingLogins,
        private RequestContextFactory $contexts,
        private AuthorizationResponder $responder,
        private InteractionPages $pages,
        private AuthenticationUtils $authentication,
        private InteractionLocale $locale,
    ) {
    }

    #[Route('/login/code', name: self::ROUTE, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $interaction = $this->browser->pending($request, $tenant, $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER));
        if ($interaction === null) {
            return $this->responder->unknownInteraction();
        }
        $this->locale->resume($request, $interaction);
        $login = $this->pendingLogins->pending($request->getSession(), $this->contexts->fromRequest($request)->receivedAt);
        if ($login === null) {
            return $this->pages->redirectToPage('heidi_interaction_login', $request);
        }

        return $this->pages->render('code.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction->request->client,
            'failed' => $this->authentication->getLastAuthenticationError() !== null,
        ]);
    }
}
