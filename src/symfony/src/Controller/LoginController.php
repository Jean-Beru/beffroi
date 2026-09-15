<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Domain\Interaction\LoginRequired;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * The login page of an interaction (architecture §4.3, §5.2). The page is reached with the identifier of
 * an interaction this browser began, before the login and again after it: the handler is resumed with
 * the session the browser holds, and the page is shown only while a login is still required, whether
 * because there is no session or because the request demands a fresh one (prompt=login, max_age).
 *
 * The POST of the form is the check path of the form login of the firewall (architecture §5.4), which
 * verifies the credentials, opens the session of the core and binds the browser to it, then sends the
 * browser back here; the route accepts POST so that the firewall may sit on it, and without a firewall a
 * POST shows the page again. A refused login comes back here too, with the failure the firewall left in
 * the HTTP session, read once and shown as one flat message whatever the reason (decision 0006, the
 * core says no more to a user).
 */
#[AsController]
final readonly class LoginController
{
    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private AuthorizationResponder $responder,
        private InteractionPages $pages,
        private AuthenticationUtils $authentication,
    ) {
    }

    #[Route('/login', name: 'heidi_interaction_login', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $interaction = $this->browser->pending($request, $tenant, $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER));
        if ($interaction === null) {
            return $this->responder->unknownInteraction();
        }
        try {
            $decision = $this->handler->resume(
                $interaction,
                $this->browser->authenticationSession($request, $tenant),
                $this->contexts->fromRequest($request),
            );
        } catch (InteractionExpiredException|InteractionCompletedException $exception) {
            return $this->responder->unresumable($request, $interaction, $exception);
        } catch (OAuth2Exception $exception) {
            return $this->responder->failure($request, $interaction->request->redirectTarget(), $exception, $interaction);
        }
        if (! $decision instanceof LoginRequired) {
            return $this->responder->respond($request, $decision);
        }

        $lastUsername = $this->authentication->getLastUsername();

        return $this->pages->render('login.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction->request->client,
            'requirement' => $decision->requirement,
            'username' => $lastUsername === '' ? $interaction->request->loginHint : $lastUsername,
            'failed' => $this->authentication->getLastAuthenticationError() !== null,
        ]);
    }
}
