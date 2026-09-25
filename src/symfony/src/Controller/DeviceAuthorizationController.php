<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\ProtocolAnswer;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Bundle\Http\Tls\PresentedClientCertificate;
use Heidi\Oidc\Application\Device\DeviceAuthorizationHandler;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationResponse;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The device authorization endpoint (RFC 8628 §3.1), POST only: where a client with no browser starts. An
 * error is the JSON of the token endpoint (§3.2), never a redirection and never a page, this client having
 * nowhere to be sent.
 */
#[AsController]
final readonly class DeviceAuthorizationController
{
    public const string ROUTE = 'heidi_protocol_device_authorization';

    public function __construct(
        private TenantProvider $tenants,
        private DeviceAuthorizationHandler $handler,
        private RequestContextFactory $contexts,
        private PresentedClientCertificate $certificates,
    ) {
    }

    #[Route('/device_authorization', name: self::ROUTE, methods: ['POST'])]
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
            return ProtocolAnswer::error($exception, DeviceAuthorizationResponse::HEADERS);
        }

        return ProtocolAnswer::json(
            $response->parameters(),
            DeviceAuthorizationResponse::STATUS_CODE,
            DeviceAuthorizationResponse::CONTENT_TYPE,
            DeviceAuthorizationResponse::HEADERS,
        );
    }
}
