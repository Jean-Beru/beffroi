<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Oidc\Application\Discovery\JwksHandler;
use Heidi\Oidc\Domain\Discovery\JwkSetResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * RFC 7517 §5: the published keys of the tenant, the ones that verify its tokens. A read, cacheable for
 * the time the set says, not at all while it is empty.
 */
#[AsController]
final readonly class JwksController
{
    public function __construct(
        private TenantProvider $tenants,
        private JwksHandler $handler,
    ) {
    }

    #[Route('/jwks', name: 'heidi_protocol_jwks', methods: ['GET'])]
    public function __invoke(): Response
    {
        $jwks = $this->handler->handle($this->tenants->provide());

        return new Response($jwks->toJson(), Response::HTTP_OK, [
            'Content-Type' => JwkSetResponse::CONTENT_TYPE,
        ] + $jwks->headers);
    }
}
