<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Oidc\Application\Token\TokenHandler;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenErrorResponse;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * RFC 6749 §3.2: the token endpoint, POST only, the client credentials in the Authorization header or in
 * the form body, the grant parameters in the form body. Success and errors are JSON (§5.1, §5.2), never
 * cached, never a redirect.
 */
#[AsController]
final readonly class TokenController
{
    private const string CONTENT_TYPE = 'application/json';

    public function __construct(
        private TenantProvider $tenants,
        private TokenHandler $handler,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route('/token', name: 'heidi_protocol_token', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                $request->headers->get('Authorization'),
                RequestParameters::ofForm($request),
                $this->contexts->fromRequest($request),
            );
        } catch (OAuth2Exception $exception) {
            $error = TokenErrorResponse::fromException($exception);

            return new Response(JwtPayload::encode($error->parameters()), $error->statusCode, [
                'Content-Type' => self::CONTENT_TYPE,
            ] + $error->headers());
        }

        return new Response(JwtPayload::encode($response->parameters()), Response::HTTP_OK, [
            'Content-Type' => self::CONTENT_TYPE,
        ] + TokenResponse::HEADERS);
    }
}
