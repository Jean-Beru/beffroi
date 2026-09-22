<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationRequestResolver;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2), GET or POST. An error of the first stage
 * is a page, one of the second goes back to the client (RFC 9700 §4.1). A request the client pushed
 * (RFC 9126 §2) arrives here as a reference, and one the client signed (RFC 9101 §6.1) as a JWT or as
 * the URL where it is published; what either of them carries is read in place of the query before
 * anything else. The locale of the interaction is chosen here, once (architecture §5.7).
 */
#[AsController]
final readonly class AuthorizationController
{
    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationRequestParser $parser,
        private PushedAuthorizationRequestResolver $pushedRequests,
        private RequestObjectResolver $requestObjects,
        private AuthorizationHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private AuthorizationResponder $responder,
        private InteractionPages $pages,
        private InteractionLocale $locale,
    ) {
    }

    #[Route('/authorize', name: 'heidi_interaction_authorize', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $parameters = RequestParameters::ofBrowserRequest($request);
        try {
            // RFC 9126 §4: a request that was pushed is read from the record and not from the query,
            // which carries nothing but the client and the reference to it
            $pushed = $this->pushedRequests->resolve($tenant, $parameters, $this->contexts->fromRequest($request));
            $parameters = $pushed ?? $parameters;
            // RFC 9101 §6.1: a request carried in a JWT is read before anything of the query is, the
            // object deciding the parameters of the request and the query nothing but which client
            // signed it. A pushed request was read at the endpoint it was pushed to and carries none.
            $parameters = $this->requestObjects->resolve($tenant, $parameters) ?? $parameters;
            $target = $this->parser->redirectTarget($tenant, $parameters, $pushed !== null);
        } catch (OAuth2Exception $exception) {
            return $this->pages->error($exception->statusCode, $exception->error, $exception->errorDescription);
        }
        try {
            $authorizationRequest = $this->parser->parse($target, $parameters);
            $locale = $this->locale->choose($request, $authorizationRequest->uiLocales);
            $this->locale->apply($request, $locale);
            $decision = $this->handler->begin(
                $authorizationRequest,
                $this->browser->authenticationSession($request, $tenant),
                $this->contexts->fromRequest($request),
                $locale,
            );
        } catch (OAuth2Exception $exception) {
            return $this->responder->failure($request, $target, $exception);
        }

        return $this->responder->respond($request, $decision);
    }
}
