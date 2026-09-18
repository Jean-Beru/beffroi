<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Oidc\Application\Revocation\RevocationHandler;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenErrorResponse;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * RFC 7009 §2: the revocation endpoint, POST only, the client credentials in the Authorization header
 * or in the form body, the token in the form body. A revoked token, and an invalid one, are answered
 * 200 with an empty body (§2.2); the errors are the ones of RFC 6749 §5.2 plus unsupported_token_type
 * (§2.2.1), as JSON, never cached, never a redirect.
 */
#[AsController]
final readonly class RevocationController
{
    public function __construct(
        private TenantProvider $tenants,
        private RevocationHandler $handler,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route('/revoke', name: 'heidi_protocol_revocation', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $this->handler->handle(
                $this->tenants->provide(),
                $request->headers->get('Authorization'),
                RequestParameters::ofForm($request),
                $this->contexts->fromRequest($request),
            );
        } catch (OAuth2Exception $exception) {
            $error = TokenErrorResponse::fromException($exception);

            return new Response(JwtPayload::encode($error->parameters()), $error->statusCode, [
                'Content-Type' => TokenErrorResponse::CONTENT_TYPE,
            ] + $error->headers());
        }

        return new Response('', Response::HTTP_OK, TokenResponse::HEADERS);
    }
}
