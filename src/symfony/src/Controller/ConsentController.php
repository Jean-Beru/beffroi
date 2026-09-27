<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\AuthorizationResponderInterface;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\FormToken;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\ConsentRequired;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The consent page of an interaction (architecture §4.3, §5.2): GET shows it, POST carries "allow" or
 * "deny" with the CSRF token.
 */
#[AsController]
final readonly class ConsentController
{
    public const string CSRF_TOKEN_ID = 'heidi_consent';

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

    #[Route('/consent', name: 'heidi_interaction_consent', methods: ['GET', 'POST'])]
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

        return $this->pages->render('consent.html.twig', [
            'interaction' => $interaction,
            'client' => $interaction->request->client,
            'user' => $decision->session->user,
            'scopes' => $decision->scopes,
            'authorization_details' => $decision->authorizationDetails,
            'requirement' => $decision->requirement,
        ]);
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
