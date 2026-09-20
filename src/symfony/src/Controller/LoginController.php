<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Session\AuthenticationMethod;
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
 * The login page of an interaction (architecture §4.3, §5.2), shown while a login is still required. The
 * POST is the check path of the form login of the firewall (§5.4), which sends the browser back here; a
 * refused login is one flat message whatever the reason (decision 0006). On a step-up (decision 0010) the
 * page says which of its two ways of signing in would satisfy the client; both stay offered, a login that
 * satisfies nothing being the way back to the client with what the session has.
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
        private InteractionLocale $locale,
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

        $lastUsername = $this->authentication->getLastUsername();
        $stepUp = $decision->stepUp;

        return $this->pages->render('login.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction->request->client,
            'requirement' => $decision->requirement,
            'step_up' => $stepUp === null ? null : [
                'classes' => $stepUp->classes,
                'password' => $stepUp->wouldBeMetBy([AuthenticationMethod::password()]),
                'passkey' => $stepUp->wouldBeMetBy(PasskeyCredential::provableMethods()),
            ],
            'username' => $lastUsername === '' ? $interaction->request->loginHint : $lastUsername,
            'failed' => $this->authentication->getLastAuthenticationError() !== null,
        ]);
    }
}
