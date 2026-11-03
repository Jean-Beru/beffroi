<?php

declare(strict_types=1);

namespace App\Controller;

use App\Doctrine\TenantProvider;
use Beffroi\Oidc\Application\Discovery\DiscoveryHandler;
use Beffroi\Oidc\Domain\Discovery\ProviderMetadata;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * OIDC Discovery §4 and RFC 8414 §3: the provider metadata of the tenant, one document at the two
 * well-known locations it is looked for at. A resource server that reads the "jwks_uri" of its
 * authorization server to verify a signed introspection response (RFC 9701) asks for the second one,
 * which is where Symfony's "oauth2" token handler looks.
 *
 * RFC 8414 §3 inserts its path between the host and the path of the issuer, where OIDC Discovery §4.1
 * appends it: the two locations are the same as long as the issuer is an origin, which is the only
 * mount `RouterEndpointLocator` accepts today. An issuer carrying a path needs this route at the
 * origin and not under the prefix the rest of the provider is mounted at.
 */
#[AsController]
final readonly class DiscoveryController
{
    public function __construct(
        private TenantProvider $tenants,
        private DiscoveryHandler $handler,
    ) {
    }

    #[Route(ProviderMetadata::OPENID_CONFIGURATION_PATH, name: 'beffroi_protocol_discovery', methods: ['GET'])]
    #[Route(ProviderMetadata::AUTHORIZATION_SERVER_METADATA_PATH, name: 'beffroi_protocol_authorization_server_metadata', methods: ['GET'])]
    public function __invoke(): Response
    {
        $metadata = $this->handler->handle($this->tenants->provide());

        return new Response($metadata->toJson(), Response::HTTP_OK, [
            'Content-Type' => ProviderMetadata::CONTENT_TYPE,
        ] + $metadata->headers);
    }
}
