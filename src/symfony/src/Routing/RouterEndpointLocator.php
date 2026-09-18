<?php

declare(strict_types=1);

namespace Heidi\Bundle\Routing;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use LogicException;
use function sprintf;
use function strlen;
use function substr;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The paths of the router under the origin of the issuer, never the Host header (architecture §4.8,
 * §5.2). A prefix that disagrees with the path of the issuer (OIDC Discovery §4.1) is refused at the
 * first request.
 */
final readonly class RouterEndpointLocator implements EndpointLocatorInterface
{
    public function __construct(
        private UrlGeneratorInterface $router,
    ) {
    }

    public function locate(Tenant $tenant): ProviderEndpoints
    {
        $issuer = $tenant->issuer->value;
        $origin = substr($issuer, 0, strlen($issuer) - strlen($tenant->issuer->path));
        $discovery = $origin . $this->router->generate('heidi_protocol_discovery', [], UrlGeneratorInterface::ABSOLUTE_PATH);
        $expected = $issuer . ProviderMetadata::OPENID_CONFIGURATION_PATH;
        if ($discovery !== $expected) {
            throw new LogicException(sprintf('The discovery document is served at "%s" but the issuer "%s" makes clients look for it at "%s" (OIDC Discovery section 4.1): mount the routes of the bundle under the path of the issuer.', $discovery, $issuer, $expected));
        }

        return new ProviderEndpoints(
            $origin . $this->router->generate('heidi_interaction_authorize', [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $origin . $this->router->generate('heidi_protocol_token', [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $origin . $this->router->generate('heidi_protocol_userinfo', [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $origin . $this->router->generate('heidi_protocol_jwks', [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $origin . $this->router->generate('heidi_interaction_logout', [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $origin . $this->router->generate('heidi_protocol_introspection', [], UrlGeneratorInterface::ABSOLUTE_PATH),
            $origin . $this->router->generate('heidi_protocol_revocation', [], UrlGeneratorInterface::ABSOLUTE_PATH),
        );
    }
}
