<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\DpopProofHeader;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Bundle\Http\Tls\PresentedClientCertificate;
use Heidi\Oidc\Application\UserInfo\UserInfoHandler;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\UserInfo\UserInfoErrorResponse;
use Heidi\Oidc\Domain\UserInfo\UserInfoResponse;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The UserInfo endpoint (OIDC Core §5.3), GET or POST; a GET hands the module no parameter at all
 * (RFC 6750 §2.3).
 */
#[AsController]
final readonly class UserInfoController
{
    public function __construct(
        private TenantProvider $tenants,
        private UserInfoHandler $handler,
        private RequestContextFactory $contexts,
        private PresentedClientCertificate $certificates,
    ) {
    }

    #[Route('/userinfo', name: 'heidi_protocol_userinfo', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                $request->getMethod(),
                $request->headers->get('Authorization'),
                $request->isMethod('POST') ? RequestParameters::ofForm($request) : [],
                $this->contexts->fromRequest($request),
                $this->certificates->ofRequest($request),
                DpopProofHeader::ofRequest($request),
            );
        } catch (OAuth2Exception|MissingBearerTokenException $exception) {
            $error = UserInfoErrorResponse::fromException($exception);
            $parameters = $error->parameters();
            if ($parameters === []) {
                return new Response('', $error->statusCode, $error->headers());
            }

            return new Response(JwtPayload::encode($parameters), $error->statusCode, [
                'Content-Type' => UserInfoResponse::CONTENT_TYPE,
            ] + $error->headers());
        }

        return new Response($response->toJson(), Response::HTTP_OK, [
            'Content-Type' => UserInfoResponse::CONTENT_TYPE,
        ] + UserInfoResponse::HEADERS);
    }
}
