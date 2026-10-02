<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\DpopProofHeader;
use Beffroi\Bundle\Http\ProtocolAnswer;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Bundle\Http\Tls\PresentedClientCertificate;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Beffroi\Oidc\Exception\OAuth2Exception;
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

    #[Route('/par', name: 'beffroi_protocol_pushed_authorization_request', methods: ['POST'])]
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
            return ProtocolAnswer::error($exception, PushedAuthorizationResponse::HEADERS);
        }

        return ProtocolAnswer::json(
            $response->parameters(),
            PushedAuthorizationResponse::STATUS_CODE,
            PushedAuthorizationResponse::CONTENT_TYPE,
            PushedAuthorizationResponse::HEADERS,
        );
    }
}
