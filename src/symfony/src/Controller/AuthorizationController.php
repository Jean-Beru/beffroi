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
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * RFC 6749 §3.1, OIDC Core §3.1.2: the authorization endpoint, GET with the parameters in the query or
 * POST with them in the form body (§3.1.2.1). The two stages of RFC 6749 §4.1.2.1 are two calls: an
 * error of the first (client, redirect URI) is a page, never a redirection; an error of the second, or of
 * the handler, goes back to the client when it may (RFC 9700 §4.1). The endpoint logs nobody in: the
 * handler parks the request and the responder sends the browser where the decision says.
 *
 * The locale of the interaction is chosen here, once (architecture §5.7): "ui_locales" of the request,
 * then the browser, then the deployment; it is recorded on the interaction and applied to this request,
 * whose pages may already be shown in it.
 */
#[AsController]
final readonly class AuthorizationController
{
    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationRequestParser $parser,
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
            $target = $this->parser->redirectTarget($tenant, $parameters);
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
