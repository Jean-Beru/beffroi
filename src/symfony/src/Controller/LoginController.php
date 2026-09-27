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
use Heidi\Bundle\Http\StepUpOffer;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Interaction\LoginRequired;
use Heidi\Oidc\Domain\Interaction\LoginRequirement;
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
 *
 * A page of the provider that is not an authorization request asks for the same two things through the
 * same form (LoginTarget): a login, when nobody is signed in, and one more proof, when somebody is and
 * what they hold does not prove what was asked of them (CIBA Core §7.1). It names no client, there being
 * no request of a browser behind it.
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
            if (! $this->loginTargets->isPending($request->getSession())) {
                return $this->responder->unknownInteraction();
            }
            $stepUp = $this->loginTargets->pendingStepUp($request->getSession());

            return $this->form(null, $stepUp === null ? null : LoginRequirement::StrongerFactorRequired, $stepUp);
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
        $stepUp = $decision->stepUp;

        return $this->form($interaction, $decision->requirement, $stepUp === null ? null : StepUpOffer::of($stepUp));
    }

    /**
     * The form, for the interaction that is waiting for a login or for the page that is: what the page says
     * of a client and of what is missing, it says of the request it serves, and a login asked for by a page
     * of the provider serves none.
     */
    private function form(?Interaction $interaction, ?LoginRequirement $requirement, ?StepUpOffer $stepUp): Response
    {
        $lastUsername = $this->authentication->getLastUsername();

        return $this->pages->render('login.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction?->request->client,
            'requirement' => $requirement,
            'step_up' => $stepUp,
            'username' => $lastUsername === '' ? $interaction?->request->loginHint : $lastUsername,
            'failed' => $this->authentication->getLastAuthenticationError() !== null,
        ]);
    }
}
