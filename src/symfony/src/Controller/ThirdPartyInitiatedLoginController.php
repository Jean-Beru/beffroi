<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Oidc\Application\Interaction\ThirdPartyInitiatedLoginHandler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The one route of the interaction plane that sends a browser to a client rather than answering one
 * (OIDC Core §4, architecture §5.2): a caller names a client of the tenant, and the browser is sent to
 * the "initiate_login_uri" that client registered, which is where the client begins the authorization
 * request this provider then answers as it answers any other.
 *
 * It takes a client and never a destination, and it holds nothing of the request it is given: what the
 * redirection carries is the module's (ThirdPartyInitiatedLogin). A browser with no session is served,
 * and gives the client no hint of whom to sign in.
 */
#[AsController]
final readonly class ThirdPartyInitiatedLoginController
{
    public const string ROUTE = 'heidi_interaction_initiate_login';

    /**
     * OIDC Core §4: the client to begin a login at, and where that client is asked to land the user.
     */
    public const string CLIENT_PARAMETER = 'client_id';

    public const string TARGET_PARAMETER = 'target_link_uri';

    /**
     * There is no login to begin here: no client of this tenant goes by that name, or the one that does
     * registered no "initiate_login_uri". One answer for both, so that asking tells nobody which clients
     * exist.
     */
    public const string NO_LOGIN_TO_BEGIN = 'no_login_to_begin';

    public function __construct(
        private TenantProvider $tenants,
        private ThirdPartyInitiatedLoginHandler $handler,
        private BrowserSession $browser,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/initiate-login', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $session = $this->browser->authenticationSession($request, $tenant);
        $login = $this->handler->handle(
            $tenant,
            $request->query->getString(self::CLIENT_PARAMETER),
            $session?->user,
            $request->query->getString(self::TARGET_PARAMETER),
        );
        if ($login === null) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, self::NO_LOGIN_TO_BEGIN);
        }

        return $this->pages->redirect($login->location());
    }
}
