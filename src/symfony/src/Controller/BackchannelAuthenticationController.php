<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\ProtocolAnswer;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Bundle\Http\Tls\PresentedClientCertificate;
use Beffroi\Oidc\Application\Ciba\BackchannelAuthenticationHandler;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationResponse;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The backchannel authentication endpoint (CIBA Core §7), POST only: where a client asks for a user it
 * names, with no browser anywhere in the request. An error is the JSON of §13, never a redirection and
 * never a page, this client having nowhere to be sent.
 */
#[AsController]
final readonly class BackchannelAuthenticationController
{
    public const string ROUTE = 'beffroi_protocol_backchannel_authentication';

    public function __construct(
        private TenantProvider $tenants,
        private BackchannelAuthenticationHandler $handler,
        private RequestContextFactory $contexts,
        private PresentedClientCertificate $certificates,
    ) {
    }

    #[Route('/backchannel_authentication', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                $request->headers->get('Authorization'),
                RequestParameters::ofForm($request),
                $this->contexts->fromRequest($request),
                $this->certificates->ofRequest($request),
            );
        } catch (OAuth2Exception $exception) {
            return ProtocolAnswer::error($exception, BackchannelAuthenticationResponse::HEADERS);
        }

        return ProtocolAnswer::json(
            $response->parameters(),
            BackchannelAuthenticationResponse::STATUS_CODE,
            BackchannelAuthenticationResponse::CONTENT_TYPE,
            BackchannelAuthenticationResponse::HEADERS,
        );
    }
}
