<?php

declare(strict_types=1);

namespace App\Routing;

use App\Controller\BackchannelAuthenticationController;
use App\Controller\ClientConfigurationReadController;
use App\Controller\ClientRegistrationController;
use App\Controller\DeviceAuthorizationController;
use App\Controller\DeviceVerificationController;
use App\Controller\PendingApprovalsController;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Domain\Discovery\ProviderMetadata;
use Beffroi\Oidc\Port\ClientConfigurationEndpointInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;
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
final readonly class RouterEndpointLocator implements ClientConfigurationEndpointInterface, EndpointLocatorInterface, MutualTlsEndpointLocatorInterface
{
    /**
     * @param string|null $mutualTlsOrigin the scheme and authority of the host that asks for a client
     *                                     certificate, null or empty for a deployment that serves none,
     *                                     an empty value being what an environment variable declared
     *                                     empty gives
     */
    public function __construct(
        private UrlGeneratorInterface $router,
        private ?string $mutualTlsOrigin = null,
    ) {
    }

    public function locate(Tenant $tenant): ProviderEndpoints
    {
        $this->assertTheRoutesAreUnderTheIssuer($tenant);

        return $this->endpointsUnder($tenant->issuer->origin());
    }

    /**
     * @throws LogicException when the routes are not mounted where the issuer makes clients look for them
     */
    private function assertTheRoutesAreUnderTheIssuer(Tenant $tenant): void
    {
        $issuer = $tenant->issuer->value;
        $discovery = $tenant->issuer->origin() . $this->path('beffroi_protocol_discovery');
        $expected = $issuer . ProviderMetadata::OPENID_CONFIGURATION_PATH;
        if ($discovery !== $expected) {
            throw new LogicException(sprintf(
                'The discovery document is served at "%s" but the issuer "%s" makes clients look for it at "%s" (OIDC Discovery section 4.1): mount the routes of the provider under the path of the issuer.',
                $discovery,
                $issuer,
                $expected,
            ));
        }
    }

    /**
     * RFC 7592 §3: the URL of one client and not of the tenant, so it is answered on its own rather than
     * among the endpoints of `ProviderEndpoints`. The path is the router's, as every other is, and the
     * origin is the issuer's: a client reads itself where it registered itself.
     */
    public function clientConfigurationFor(Tenant $tenant, string $clientId): string
    {
        $this->assertTheRoutesAreUnderTheIssuer($tenant);

        return (
            $tenant->issuer->origin()
            . $this->router->generate(
                ClientConfigurationReadController::ROUTE,
                [
                    ClientConfigurationReadController::CLIENT_ID => $clientId,
                ],
                UrlGeneratorInterface::ABSOLUTE_PATH,
            )
        );
    }

    /**
     * The endpoints of the tenant as a client presenting a certificate reaches them: the paths of the
     * router, which already carry the prefix the provider is mounted under, on the other origin. The
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
            $origin . $this->path('beffroi_interaction_authorize'),
            $origin . $this->path('beffroi_protocol_token'),
            $origin . $this->path('beffroi_protocol_userinfo'),
            $origin . $this->path('beffroi_protocol_jwks'),
            $origin . $this->path('beffroi_interaction_logout'),
            $origin . $this->path('beffroi_protocol_introspection'),
            $origin . $this->path('beffroi_protocol_revocation'),
            $origin . $this->path('beffroi_protocol_pushed_authorization_request'),
            $origin . $this->path(DeviceAuthorizationController::ROUTE),
            $origin . $this->path(DeviceVerificationController::ROUTE),
            $origin . $this->path(BackchannelAuthenticationController::ROUTE),
            $origin . $this->path(PendingApprovalsController::ROUTE),
            $origin . $this->path(ClientRegistrationController::ROUTE),
        );
    }

    private function path(string $route): string
    {
        return $this->router->generate($route, [], UrlGeneratorInterface::ABSOLUTE_PATH);
    }
}
