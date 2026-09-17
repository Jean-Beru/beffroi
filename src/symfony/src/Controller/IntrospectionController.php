<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Oidc\Application\Introspection\IntrospectionHandler;
use Heidi\Oidc\Domain\Introspection\IntrospectionResponse;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenErrorResponse;
use Heidi\Oidc\Exception\OAuth2Exception;
use function in_array;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * RFC 7662 §2: the introspection endpoint, POST only, the client credentials in the Authorization header
 * or in the form body, the token in the form body. The answer is JSON, or the signed JWT of RFC 9701
 * when the Accept header asks for its media type (§4), never cached, never a redirect. A failure to
 * authenticate the caller is the error of RFC 6749 §5.2 (§2.3), with the challenge when the header was
 * used.
 */
#[AsController]
final readonly class IntrospectionController
{
    public function __construct(
        private TenantProvider $tenants,
        private IntrospectionHandler $handler,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route('/introspect', name: 'heidi_protocol_introspection', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                $request->headers->get('Authorization'),
                RequestParameters::ofForm($request),
                $this->contexts->fromRequest($request),
                in_array(IntrospectionResponse::JWT_CONTENT_TYPE, $request->getAcceptableContentTypes(), true),
            );
        } catch (OAuth2Exception $exception) {
            $error = TokenErrorResponse::fromException($exception);

            return new Response(JwtPayload::encode($error->parameters()), $error->statusCode, [
                'Content-Type' => TokenErrorResponse::CONTENT_TYPE,
            ] + $error->headers());
        }

        return new Response($response->body(), Response::HTTP_OK, [
            'Content-Type' => $response->contentType(),
        ] + IntrospectionResponse::HEADERS);
    }
}
