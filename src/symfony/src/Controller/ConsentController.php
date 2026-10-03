<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionLocale;
use Beffroi\Bundle\Http\FormToken;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Oidc\Application\Authorization\AuthorizationHandler;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\ConsentPage;
use Beffroi\Oidc\Domain\Interaction\ConsentRequired;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The consent page of an interaction (architecture §4.3, §5.2): GET shows it, POST carries "allow" or
 * "deny" with the CSRF token.
 *
 * What the page says of the client that is asking, and the Content-Security-Policy that goes with it,
 * are the module's (ConsentPage); this renders them from a template an application may override, as the
 * form post response and the front-channel logout page are rendered.
 */
#[AsController]
final readonly class ConsentController
{
    public const string CSRF_TOKEN_ID = 'beffroi_consent';

    public const string ANSWER_ALLOW = 'allow';

    public const string ANSWER_DENY = 'deny';

    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private AuthorizationResponderInterface $responder,
        private InteractionPages $pages,
        private FormToken $formTokens,
        private InteractionLocale $locale,
    ) {
    }

    #[Route('/consent', name: 'beffroi_interaction_consent', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $parameters = RequestParameters::ofBrowserRequest($request);
        $id = $parameters[AuthorizationResponder::INTERACTION_PARAMETER] ?? null;
        $interaction = $this->browser->pending($request, $tenant, is_string($id) ? $id : null);
        if ($interaction === null) {
            return $this->responder->unknownInteraction();
        }
        $this->locale->resume($request, $interaction);
        if ($request->isMethod('POST')) {
            $refusal = $this->formTokens->refusal($parameters[FormToken::PARAMETER] ?? null, self::CSRF_TOKEN_ID);
            if ($refusal !== null) {
                return $refusal;
            }
        }
        try {
            $decision = $this->decide($request, $interaction, $parameters);
        } catch (InteractionExpiredException|InteractionCompletedException $exception) {
            return $this->responder->unresumable($request, $interaction, $exception);
        } catch (OAuth2Exception $exception) {
            return $this->responder->failure($request, $interaction->request->redirectTarget(), $exception, $interaction);
        }
        if (! $decision instanceof ConsentRequired) {
            return $this->responder->respond($request, $decision);
        }

        // the page shows the logo of the client and the one of the tenant, so its policy names where both
        // are served from (ConsentPage); it is the one page whose policy is part of its answer
        $page = new ConsentPage($interaction->request->client->registration->presentation, $tenant->look);

        return $this->pages->render(
            'consent.html.twig',
            [
                'interaction' => $interaction,
                'client' => $interaction->request->client,
                'page' => $page,
                'user' => $decision->session->user,
                'scopes' => $decision->scopes,
                'authorization_details' => $decision->authorizationDetails,
                'requirement' => $decision->requirement,
            ],
            headers: [
                'Content-Security-Policy' => $page->contentSecurityPolicy(),
            ],
        );
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws InteractionExpiredException
     * @throws InteractionCompletedException
     * @throws OAuth2Exception
     */
    private function decide(Request $request, Interaction $interaction, array $parameters): AuthorizationDecision
    {
        $tenant = $this->tenants->provide();
        $session = $this->browser->authenticationSession($request, $tenant);
        $context = $this->contexts->fromRequest($request);
        if (! $request->isMethod('POST')) {
            return $this->handler->resume($interaction, $session, $context);
        }
        $answer = $parameters['answer'] ?? null;
        if ($answer === self::ANSWER_DENY) {
            $this->handler->deny($interaction);
        }
        if ($answer !== self::ANSWER_ALLOW || $session === null) {
            return $this->handler->resume($interaction, $session, $context);
        }

        return $this->handler->grantConsent($interaction, $session, $context);
    }
}
