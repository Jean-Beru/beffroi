<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationRequestReaderInterface;
use Heidi\Bundle\Http\AuthorizationResponderInterface;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2), GET or POST. An error of the first stage
 * is a page, one of the second goes back to the client (RFC 9700 §4.1). A request the client pushed
 * (RFC 9126 §2) arrives here as a reference, and one the client signed (RFC 9101 §6.1) as a JWT or as
 * the URL where it is published; the reader answers with what either of them carries, in place of the
 * query. The locale of the interaction is chosen here, once (architecture §5.7).
 */
#[AsController]
final readonly class AuthorizationController
{
    public function __construct(
        private TenantProvider $tenants,
        private AuthorizationRequestReaderInterface $requests,
        private AuthorizationRequestParser $parser,
        private AuthorizationHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private AuthorizationResponderInterface $responder,
        private InteractionPages $pages,
        private InteractionLocale $locale,
    ) {
    }

    #[Route('/authorize', name: 'heidi_interaction_authorize', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        try {
            $received = $this->requests->read($tenant, $request);
            $target = $this->parser->redirectTarget($tenant, $received->parameters, $received->pushed, $received->carriedByObject);
        } catch (OAuth2Exception $exception) {
            return $this->pages->error($exception->statusCode, $exception->error, $exception->errorDescription);
        }
        try {
            $authorizationRequest = $this->parser->parse($target, $received->parameters);
            $locale = $this->locale->choose($request, $authorizationRequest->uiLocales);
            $this->locale->apply($request, $locale);
            $decision = $this->handler->begin(
                $authorizationRequest,
                $this->browser->authenticationSession($request, $tenant),
                $this->contexts->fromRequest($request),
                $locale,
                $received->requestUriHash,
            );
        } catch (OAuth2Exception $exception) {
            return $this->responder->failure($request, $target, $exception);
        }

        return $this->responder->respond($request, $decision);
    }
}
