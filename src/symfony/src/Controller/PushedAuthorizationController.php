<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\DpopProofHeader;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Bundle\Http\Tls\PresentedClientCertificate;
use Heidi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenErrorResponse;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The pushed authorization request endpoint (RFC 9126 §2), POST only. A success is a 201 (§2.2); an
 * error is the JSON of the token endpoint (§2.3), never a redirection and never a page, even when the
 * request names a redirect URI the provider would otherwise have answered to.
 */
#[AsController]
final readonly class PushedAuthorizationController
{
    public function __construct(
        private TenantProvider $tenants,
        private PushedAuthorizationHandler $handler,
        private RequestContextFactory $contexts,
        private PresentedClientCertificate $certificates,
    ) {
    }

    #[Route('/par', name: 'heidi_protocol_pushed_authorization_request', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                $request->headers->get('Authorization'),
                RequestParameters::ofForm($request),
                $this->contexts->fromRequest($request),
                $this->certificates->ofRequest($request),
                DpopProofHeader::ofRequest($request),
            );
        } catch (OAuth2Exception $exception) {
            $error = TokenErrorResponse::fromException($exception);

            return new Response(JwtPayload::encode($error->parameters()), $error->statusCode, [
                'Content-Type' => TokenErrorResponse::CONTENT_TYPE,
            ]
            + PushedAuthorizationResponse::HEADERS
            + $error->headers());
        }

        return new Response(JwtPayload::encode($response->parameters()), PushedAuthorizationResponse::STATUS_CODE, [
            'Content-Type' => PushedAuthorizationResponse::CONTENT_TYPE,
        ] + PushedAuthorizationResponse::HEADERS);
    }
}
