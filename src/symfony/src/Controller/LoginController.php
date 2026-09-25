<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\AuthorizationResponderInterface;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\LoginTarget;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Domain\Interaction\Interaction;
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
 * The login page of an interaction (architecture §4.3, §5.2), shown while a login is still required. The
 * POST is the check path of the form login of the firewall (§5.4), which sends the browser back here; a
 * refused login is one flat message whatever the reason (decision 0006). On a step-up (decision 0010) the
 * page says which of the credentials the user holds would satisfy the client, by their kinds as the
 * StepUp names them, a passkey, the password, a TOTP after the password; both forms stay offered, a login
 * that satisfies nothing being the way back to the client with what the session has.
 */
#[AsController]
final readonly class LoginController
{
    public const string ROUTE = 'heidi_interaction_login';

    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private AuthorizationResponderInterface $responder,
        private InteractionPages $pages,
        private AuthenticationUtils $authentication,
        private InteractionLocale $locale,
        private LoginTarget $loginTargets,
    ) {
    }

    #[Route('/login', name: self::ROUTE, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $interaction = $this->browser->pending($request, $tenant, $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER));
        if ($interaction === null) {
            // a page of the provider that is not an authorization request asked for this login and is
            // waiting for it: the form is the same one, and there is no interaction to resume
            return $this->loginTargets->isPending($request->getSession())
                ? $this->form(null, null)
                : $this->responder->unknownInteraction();
        }
        $this->locale->resume($request, $interaction);
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

        return $this->form($interaction, $decision);
    }

    /**
     * The form, for the interaction that is waiting for a login or for the page that is: what the page says
     * of a client and of what is missing, it says of the request it serves, and a login asked for by a page
     * of the provider serves none.
     */
    private function form(?Interaction $interaction, ?LoginRequired $decision): Response
    {
        $lastUsername = $this->authentication->getLastUsername();

        return $this->pages->render('login.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction?->request->client,
            'requirement' => $decision?->requirement,
            'step_up' => $decision?->stepUp,
            'username' => $lastUsername === '' ? $interaction?->request->loginHint : $lastUsername,
            'failed' => $this->authentication->getLastAuthenticationError() !== null,
        ]);
    }
}
