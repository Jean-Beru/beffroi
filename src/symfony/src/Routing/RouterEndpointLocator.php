<?php

declare(strict_types=1);

namespace Heidi\Bundle\Routing;

use Heidi\Bundle\Controller\BackchannelAuthenticationController;
use Heidi\Bundle\Controller\DeviceAuthorizationController;
use Heidi\Bundle\Controller\DeviceVerificationController;
use Heidi\Bundle\Controller\PendingApprovalsController;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use LogicException;
use function rtrim;
use function sprintf;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The paths of the router under the origin of the issuer, never the Host header (architecture §4.8,
 * §5.2). A prefix that disagrees with the path of the issuer (OIDC Discovery §4.1) is refused at the
 * first request.
 *
 * A deployment that serves a host whose TLS listener asks for a client certificate names its origin, and
 * the endpoints are located a second time under it (RFC 8705 §5): the same application, the same paths,
 * another way in. The two sets are built here and not written down twice, so that a route that moves
 * moves in both.
 */
final readonly class RouterEndpointLocator implements EndpointLocatorInterface, MutualTlsEndpointLocatorInterface
{
    /**
     * @param string|null $mutualTlsOrigin the scheme and authority of the host that asks for a client
     *                                     certificate, null or empty for a deployment that serves none,
     *                                     an empty value being what an environment variable nobody set
     *                                     gives
     */
    public function __construct(
        private UrlGeneratorInterface $router,
        private ?string $mutualTlsOrigin = null,
    ) {
    }

    public function locate(Tenant $tenant): ProviderEndpoints
    {
        $issuer = $tenant->issuer->value;
        $origin = $tenant->issuer->origin();
        $discovery = $origin . $this->path('heidi_protocol_discovery');
        $expected = $issuer . ProviderMetadata::OPENID_CONFIGURATION_PATH;
        if ($discovery !== $expected) {
            throw new LogicException(sprintf(
                'The discovery document is served at "%s" but the issuer "%s" makes clients look for it at "%s" (OIDC Discovery section 4.1): mount the routes of the bundle under the path of the issuer.',
                $discovery,
                $issuer,
                $expected,
            ));
        }

        return $this->endpointsUnder($origin);
    }

    /**
     * The endpoints of the tenant as a client presenting a certificate reaches them: the paths of the
     * router, which already carry the prefix the bundle is mounted under, on the other origin. The
     * issuer does not change, and neither does what the document says of itself: an alias is another way
     * to the same provider, not another provider (RFC 8705 §5).
     */
    public function locateMutualTls(Tenant $tenant): ?ProviderEndpoints
    {
        $origin = rtrim($this->mutualTlsOrigin ?? '', '/');
        if ($origin === '') {
            return null;
        }

        return $this->endpointsUnder($origin);
    }

    private function endpointsUnder(string $origin): ProviderEndpoints
    {
        return new ProviderEndpoints(
            $origin . $this->path('heidi_interaction_authorize'),
            $origin . $this->path('heidi_protocol_token'),
            $origin . $this->path('heidi_protocol_userinfo'),
            $origin . $this->path('heidi_protocol_jwks'),
            $origin . $this->path('heidi_interaction_logout'),
            $origin . $this->path('heidi_protocol_introspection'),
            $origin . $this->path('heidi_protocol_revocation'),
            $origin . $this->path('heidi_protocol_pushed_authorization_request'),
            $origin . $this->path(DeviceAuthorizationController::ROUTE),
            $origin . $this->path(DeviceVerificationController::ROUTE),
            $origin . $this->path(BackchannelAuthenticationController::ROUTE),
            $origin . $this->path(PendingApprovalsController::ROUTE),
        );
    }

    private function path(string $route): string
    {
        return $this->router->generate($route, [], UrlGeneratorInterface::ABSOLUTE_PATH);
    }
}
