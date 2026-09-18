<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Oidc\Application\Discovery\DiscoveryHandler;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * OIDC Discovery §4: the provider metadata of the tenant.
 */
#[AsController]
final readonly class DiscoveryController
{
    public function __construct(
        private TenantProvider $tenants,
        private DiscoveryHandler $handler,
    ) {
    }

    #[Route(ProviderMetadata::OPENID_CONFIGURATION_PATH, name: 'heidi_protocol_discovery', methods: ['GET'])]
    public function __invoke(): Response
    {
        $metadata = $this->handler->handle($this->tenants->provide());

        return new Response($metadata->toJson(), Response::HTTP_OK, [
            'Content-Type' => ProviderMetadata::CONTENT_TYPE,
        ] + $metadata->headers);
    }
}
