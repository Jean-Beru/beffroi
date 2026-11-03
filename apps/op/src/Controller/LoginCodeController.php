<?php

declare(strict_types=1);

namespace App\Controller;

use App\Doctrine\TenantProvider;
use App\Http\AuthorizationResponder;
use App\Http\AuthorizationResponderInterface;
use App\Http\BrowserSession;
use App\Http\FormTarget;
use App\Http\InteractionLocale;
use App\Http\InteractionPages;
use App\Http\LoginTarget;
use App\Http\PendingLoginStore;
use App\Http\RequestContextFactory;
use App\Security\CodeRefusal;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * The code page of an interaction (architecture §5.2, §5.4), shown to a browser whose password login is
 * held until a code: the code of the authenticator app, or a backup code, in one field. The POST is the
 * check path of the TOTP authenticator of the firewall, which sends the browser back here on a refusal,
 * with the message of the shape that was typed and never of the reason it was refused (CodeRefusal,
 * decision 0006), or to the login page on a success, which resumes the interaction. Without a login
 * pending, or once it expired, the password is typed again.
 */
#[AsController]
final readonly class LoginCodeController
{
    public const string ROUTE = 'beffroi_interaction_login_code';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private PendingLoginStore $pendingLogins,
        private RequestContextFactory $contexts,
        private AuthorizationResponderInterface $responder,
        private InteractionPages $pages,
        private AuthenticationUtils $authentication,
        private InteractionLocale $locale,
        private LoginTarget $loginTargets,
        private FormTarget $formTargets,
    ) {
    }

    #[Route('/login/code', name: self::ROUTE, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $interaction = $this->browser->pending($request, $tenant, $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER));
        if ($interaction === null && ! $this->loginTargets->isPending($request->getSession())) {
            return $this->responder->unknownInteraction();
        }
        if ($interaction !== null) {
            $this->locale->resume($request, $interaction);
            // the code this page asks for ends the login, and the login ends where the client asked to be
            // answered, which its policy names (FormTarget)
            $this->formTargets->mayEndAt($request, $interaction->request->redirectUri);
        }
        // a browser holding no login, or one that has run out of time, has a password to type again; what
        // a code typed late is refused as is the second step's, and the core announces it (issue #130)
        $login = $this->pendingLogins->held($request->getSession());
        if ($login === null || $login->isExpired($this->contexts->fromRequest($request)->receivedAt)) {
            return $this->pages->redirectToPage(LoginController::ROUTE, $request);
        }

        return $this->pages->render('code.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction?->request->client,
            'refusal' => CodeRefusal::shown($this->authentication->getLastAuthenticationError()),
        ]);
    }
}
